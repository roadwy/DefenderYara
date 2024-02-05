
rule Trojan_Win32_Dridex_CW_MTB{
	meta:
		description = "Trojan:Win32/Dridex.CW!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {81 f6 4b 9a f7 94 2b 75 20 83 c6 2b 81 ee 2c 37 7c a4 } //0a 00 
		$a_01_1 = {03 4d 20 83 e9 13 81 f1 fa 2b 8d e2 03 c8 } //00 00 
	condition:
		any of ($a_*)
 
}