import re
from datetime import datetime, timedelta, time
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# 读取日志文件
log_file = "boofuzz-picoquic.txt"  # 请替换为实际路径
original_times = []
times = []
counts = []

# 配置纵坐标轴
def custom_yticks():
    """创建分段刻度系统"""
    # 基础分段
    lower_ticks = [0]
    upper_ticks = list(range(2000, 2601, 100))
    
    # 组合刻度
    full_ticks = lower_ticks + upper_ticks
    
    # 生成标签（隐藏2000以下的中间值）
    labels = []
    for t in full_ticks:
        if t == 0:
            labels.append("0")
        elif t >= 2000:
            labels.append(str(t))
        else:
            labels.append("")  # 隐藏2000以下的其他刻度标签
    
    return full_ticks, labels


with open(log_file, 'r') as f:
    for line in f:
        match = re.search(r'\[(.*?) INFO.*?count_bytes/total_bytes: (\d+)/', line)
        if match:
            # 解析原始时间戳
            raw_time = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%SZ")
            original_times.append(raw_time)
            counts.append(int(match.group(2)))

# 计算时间基准
if not original_times:
    raise ValueError("No valid timestamps found")

base_date = original_times[0].date()  # 取第一个日志的日期
day_start = datetime.combine(base_date, time.min)  # 当日00:00:00
day_end = day_start + timedelta(days=1)  # 次日00:00:00
print(day_start, day_end)
# print(f"Base date: {original_times}")
# 生成相对时间序列
for t in original_times:
    new_time = t - original_times[0] + day_start
    times.append(new_time)
# times = [datetime.combine(base_date, t.timetz()) for t in original_times]  # 保留时间部分，日期对齐到base_date
# print(f"Times: {times}")

# 创建可视化
plt.figure(figsize=(16, 6))
ax = plt.gca()

# 绘制趋势线
ax.plot(times, counts, linestyle='-', linewidth=1.8, color='#4C72B0')

# 配置时间轴
ax.set_xlim(day_start, day_end)  # 强制24小时范围
ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
ax.xaxis.set_major_locator(mdates.HourLocator(interval=4))  # 每3小时主刻度
ax.xaxis.set_minor_locator(mdates.HourLocator())  # 每小时次刻度

# 智能Y轴配置
data_min = min(counts)
data_max = max(counts)
buffer = max(50, (data_max - data_min) * 0.2)  # 动态缓冲计算
ax.set_ylim(0, 2600)  # 包含完整范围
yticks, ylabels = custom_yticks()
ax.set_yticks(yticks)
ax.set_yticklabels(ylabels)
ax.axhline(2000, color='gray', linestyle='--', linewidth=0.8, alpha=0.6)


# 增强网格系统
ax.grid(which='major', linewidth=1.2, linestyle='--', alpha=0.8)
ax.grid(which='minor', linewidth=0.6, linestyle=':', alpha=0.5)

# 标签美化
ax.set_xlabel("Elapsed Time (HH:MM)", fontsize=12, labelpad=12)
ax.set_ylabel("Covered Edges", fontsize=12, labelpad=12)
ax.set_title("24-Hour Coverage Progression", fontsize=14, pad=18)

# 优化时间标签旋转
plt.xticks(rotation=45, ha='right')

# 紧凑布局
plt.tight_layout()
plt.show()