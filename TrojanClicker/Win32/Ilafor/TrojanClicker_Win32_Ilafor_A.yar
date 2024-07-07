
rule TrojanClicker_Win32_Ilafor_A{
	meta:
		description = "TrojanClicker:Win32/Ilafor.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 fb 02 75 06 c6 45 90 01 01 70 eb 04 c6 45 90 01 01 71 90 00 } //1
		$a_03_1 = {fe cb 74 1d fe cb 0f 84 90 01 02 00 00 90 00 } //1
		$a_01_2 = {2a 71 3d 2a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}