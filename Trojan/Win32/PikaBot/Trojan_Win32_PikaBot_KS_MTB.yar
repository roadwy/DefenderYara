
rule Trojan_Win32_PikaBot_KS_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 f6 f1 af 31 92 90 01 05 b0 90 01 01 79 90 01 01 25 90 01 04 c4 b7 90 01 04 46 e3 90 01 05 e8 a8 90 01 03 e9 90 00 } //01 00 
		$a_03_1 = {9e 02 cf b5 90 01 01 b3 90 01 01 a9 90 01 05 e8 b4 90 01 03 e9 90 00 } //01 00 
		$a_01_2 = {43 72 61 73 68 } //00 00  Crash
	condition:
		any of ($a_*)
 
}