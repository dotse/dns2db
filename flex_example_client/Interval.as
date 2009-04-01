package 
{
   public class Interval
   {
      function Interval(datum:Date,hour:int,min:int)
      {
         Datum = datum;
         HTid = hour;
         MTid = min;
      }
      public function touch():void 
      {
         touch_count++;
      }
      public var Datum:Date = null;
      public var HTid:int = 0;
      public var MTid:int = 0;
      public var touch_count:int = 0;
   }
}