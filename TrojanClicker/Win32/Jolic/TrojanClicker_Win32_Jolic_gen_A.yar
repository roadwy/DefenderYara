
rule TrojanClicker_Win32_Jolic_gen_A{
	meta:
		description = "TrojanClicker:Win32/Jolic.gen!A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 74 70 6c 00 75 } //1 琽汰甀
		$a_01_1 = {3d 70 61 67 65 75 } //1 =pageu
		$a_01_2 = {3d 72 65 71 00 75 } //1 爽煥甀
		$a_01_3 = {3d 75 70 64 00 75 } //1 甽摰甀
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}