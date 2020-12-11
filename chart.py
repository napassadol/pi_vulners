import pandas as pd
import matplotlib.pyplot as plt

def createPieChart(low, medium, high):
    labels = 'LOW', 'MEDIUM', 'HIGH'
    sizes = [low, medium, high]
    explode = (0, 0, 0)

    fig1, ax1 = plt.subplots()
    ax1.pie(sizes, explode=explode, labels=labels, autopct='%1.1f%%', shadow=False, startangle=90)
    ax1.axis('equal')

    plt.savefig('plot.png', dpi=300, bbox_inches='tight')
