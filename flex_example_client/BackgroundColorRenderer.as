package
{
import mx.controls.DataGrid;
import mx.controls.dataGridClasses.DataGridItemRenderer;
import mx.controls.dataGridClasses.DataGridListData;
import mx.controls.dataGridClasses.DataGridColumn;

public class BackgroundColorRenderer extends DataGridItemRenderer
{

	public function BackgroundColorRenderer()
	{
		super();
	}

	/**
	 *  DataGridItemRenderer extends TextField and has a slightly different
	 *  validation mechanism than UIComponent-based widgets.  All visuals
	 *  are resolved within the validateNow call.  We apply the background
	 *  here
	 */
	override public function validateNow():void
	{
		super.validateNow();

		if (!listData) 
		{
			// item renderers are recycled so you have to make sure
			// that all code paths lead to a known state.
			background = false;
			return;
		}

		var dgListData:DataGridListData = listData as DataGridListData;
		var dataGrid:DataGrid = dgListData.owner as DataGrid;

		// comment this out if you want to see the background over the
		// selection and highlight indicators
		if (dataGrid.isItemSelected(data) || dataGrid.isItemHighlighted(data))
		{
			// clear the background so you can see the selection/highlight colors
			background = false;
			return;
		}

		var column:DataGridColumn = dataGrid.columns[dgListData.columnIndex];
		//if (data[column.dataField]
		{
			// TextFields can draw solid color backgrounds.  Can't do gradients though
			background = true;
			backgroundColor = 0xFF0000 | ((0xfe00*(100-data[column.dataField])/100)&0xff00) | ((0xfe*(100-data[column.dataField])/100)&0xff);
		}
		//else
			//background = false;
	}

}

}
