use std::{fs::File, io::Read, thread::sleep, time::Duration};

// 获取进程在 `/proc/[pid]/stat` 中的 CPU 时间
pub fn get_process_cpu_time(pid: u32) -> Option<(u64, u64)> {
    let stat_file_path = format!("/proc/{}/stat", pid);
    let mut stat_file = File::open(stat_file_path).ok()?;
    let mut stat_content = String::new();
    stat_file.read_to_string(&mut stat_content).ok()?;
    
    // 拆分 stat 文件内容
    let stats: Vec<&str> = stat_content.split_whitespace().collect();

    if stats.len() > 15 {
        // utime (14), stime (15) 分别是用户态和系统态时间
        let utime: u64 = stats[13].parse().ok()?;
        let stime: u64 = stats[14].parse().ok()?;
        return Some((utime, stime));
    }

    None
}

pub fn get_cpu_time(cpu_ids: &[u32]) -> Option<Vec<(u64, u64)>> {
    let mut file = File::open("/proc/stat").ok()?;
    let mut content = String::new();
    file.read_to_string(&mut content).ok()?;

    let mut cpu_times = Vec::new();

    for line in content.lines() {
        if line.starts_with("cpu") && !line.starts_with("cpu ") {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }

            // 获取 CPU 编号 (例如 cpu0, cpu1 等)
            let cpu_id: u32 = fields[0][3..].parse().ok()?;
            
            // 只关心指定的 CPU 核心
            if cpu_ids.contains(&cpu_id) {
                // 将每个字段解析为 u64，如果失败则返回 None
                let user_time: u64 = fields[1].parse().ok()?;
                let system_time: u64 = fields[3].parse().ok()?;
                let idle_time: u64 = fields[4].parse().ok()?;
                
                let user_system_time = user_time + system_time;
                cpu_times.push((user_system_time, idle_time));
            }
        }
    }

    if cpu_times.is_empty() {
        None
    } else {
        Some(cpu_times)
    }
}


// 计算 CPU 占用率
pub fn calculate_cpu_usage(
    prev_process_time: (u64, u64),
    curr_process_time: (u64, u64),
    prev_cpu_times: Vec<(u64, u64)>,
    curr_cpu_times: Vec<(u64, u64)>
) -> f64 {
    let prev_process_total = prev_process_time.0 + prev_process_time.1;
    let curr_process_total = curr_process_time.0 + curr_process_time.1;
    let process_diff = curr_process_total.saturating_sub(prev_process_total);

    let mut cpu_diff = 0;
    for (prev_cpu, curr_cpu) in prev_cpu_times.iter().zip(curr_cpu_times.iter()) {
        let prev_cpu_total = prev_cpu.0 + prev_cpu.1;
        let curr_cpu_total = curr_cpu.0 + curr_cpu.1;
        cpu_diff += curr_cpu_total.saturating_sub(prev_cpu_total);
    }

    if cpu_diff == 0 {
        return 0.0;
    }

    // 计算 CPU 使用率
    100.0 * process_diff as f64 / cpu_diff as f64
}

fn main() {
    let pid: u32 = 588337; // 将此处替换为你要监控的进程A的PID
    let cpu_ids = vec![50, 51,52,53]; // 假设进程绑定了 CPU0 和 CPU1
    let interval = Duration::from_secs(1);

    loop {
        // 获取初始的进程和指定CPU核心的时间
        let prev_process_time = get_process_cpu_time(pid).expect("Failed to get process CPU time");
        let prev_cpu_times = get_cpu_time(&cpu_ids).expect("Failed to get CPU core times");

        // 等待一段时间
        sleep(interval);

        // 获取当前的进程和指定CPU核心的时间
        let curr_process_time = get_process_cpu_time(pid).expect("Failed to get process CPU time");
        let curr_cpu_times = get_cpu_time(&cpu_ids).expect("Failed to get CPU core times");

        // 计算 CPU 占用率
        let cpu_usage = calculate_cpu_usage(prev_process_time, curr_process_time, prev_cpu_times, curr_cpu_times);
        //println!("Process {} CPU Usage on cores {:?}: {:.2}%", pid, cpu_ids, cpu_usage);
    }
}