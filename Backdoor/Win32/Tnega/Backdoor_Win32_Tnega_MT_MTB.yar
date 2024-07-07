
rule Backdoor_Win32_Tnega_MT_MTB{
	meta:
		description = "Backdoor:Win32/Tnega.MT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 07 66 a9 84 38 c0 de aa c0 ea 28 66 8b 57 04 81 fc 15 46 19 29 f7 c6 df 39 23 1d 81 c7 06 00 00 00 36 66 89 10 2d 9b 1f cd 71 0f c8 d2 dc 81 ee 04 00 00 00 8b 06 33 c3 f5 0f c8 f5 c1 c8 02 e9 9b df 09 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}