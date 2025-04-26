
rule TrojanClicker_Win32_Popagerty_A{
	meta:
		description = "TrojanClicker:Win32/Popagerty.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 6f 70 75 70 67 75 69 64 65 5c 64 61 74 61 2e 64 62 } //2 popupguide\data.db
		$a_01_1 = {63 6f 75 6e 74 65 72 2e 70 6f 70 2d 75 70 67 75 69 64 65 2e 63 6f 6d } //2 counter.pop-upguide.com
		$a_01_2 = {70 6f 70 75 70 67 75 69 64 65 5c 73 6f 75 72 63 65 5c 4d 61 69 6e 55 2e 70 61 73 } //2 popupguide\source\MainU.pas
		$a_01_3 = {69 6c 69 6b 65 63 6c 69 63 6b 2e 63 6f 6d 2f 74 72 61 63 6b 2f 63 6c 69 63 6b 2e 70 68 70 } //1 ilikeclick.com/track/click.php
		$a_01_4 = {70 6f 70 75 70 67 75 69 64 65 5f 30 32 } //1 popupguide_02
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}