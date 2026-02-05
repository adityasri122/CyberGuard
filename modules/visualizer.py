import pyqtgraph as pg
from PySide6.QtWidgets import QWidget, QVBoxLayout
from PySide6.QtGui import QFont, QColor
from collections import Counter

# Set a white background for the charts
pg.setConfigOption('background', 'w')
pg.setConfigOption('foreground', 'k')

class PasswordBarChart(QWidget):
    """
    A custom widget that displays a bar chart of password strengths.
    """
    def __init__(self):
        super().__init__()
        
        self.layout = QVBoxLayout(self)
        
        # Create a plot widget
        self.plot_widget = pg.PlotWidget()
        self.layout.addWidget(self.plot_widget)
        
        # Set chart properties
        self.plot_widget.setTitle("Password Strength Distribution", color='k', size='16pt')
        self.plot_widget.setLabel('left', 'Password Count', color='k')
        self.plot_widget.setLabel('bottom', 'Strength Verdict', color='k')
        self.plot_widget.showGrid(y=True, alpha=0.3)
        
        # Define the categories in a logical order
        self.categories = ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong', 'Empty']
        # Define the colors for each bar
        self.color_map = {
            'Very Weak': '#E74C3C', # Red
            'Weak': '#E67E22',      # Orange
            'Moderate': '#F1C40F',  # Yellow
            'Strong': '#27AE60',    # Green
            'Very Strong': '#2ECC71',# Bright Green
            'Empty': '#95A5A6'       # Gray
        }
        
        # Create the bar graph item
        self.bar_item = pg.BarGraphItem(
            x=[], 
            height=[], 
            width=0.6, 
            brushes=[]
        )
        self.plot_widget.addItem(self.bar_item)
        
        # Set X-axis labels
        ticks = [(i, self.categories[i]) for i in range(len(self.categories))]
        self.plot_widget.getAxis('bottom').setTicks([ticks])
        
        self.update_chart([]) # Initialize with empty data

    def update_chart(self, password_list):
        """
        Clears and redraws the bar chart with new data.
        """
        if not password_list:
            # Set to empty if no data
            self.bar_item.setOpts(x=[], height=[], brushes=[])
            return

        # 1. Count the verdicts
        verdicts = [p.get('strength_verdict', 'N/A') for p in password_list]
        counts = Counter(verdicts)
        
        # 2. Prepare data for the bar chart
        x_positions = []
        heights = []
        brushes = []
        
        for i, category in enumerate(self.categories):
            count = counts.get(category, 0)
            
            x_positions.append(i)
            heights.append(count)
            brushes.append(self.color_map.get(category, '#34495E'))

        # 3. Update the bar chart
        self.bar_item.setOpts(x=x_positions, height=heights, brushes=brushes)
        
        # Re-set X-axis labels (in case they were cleared)
        ticks = [(i, self.categories[i]) for i in range(len(self.categories))]
        self.plot_widget.getAxis('bottom').setTicks([ticks])