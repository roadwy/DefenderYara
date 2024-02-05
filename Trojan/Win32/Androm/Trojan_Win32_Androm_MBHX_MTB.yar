
rule Trojan_Win32_Androm_MBHX_MTB{
	meta:
		description = "Trojan:Win32/Androm.MBHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 33 00 65 00 34 00 64 00 33 00 64 00 34 00 32 00 34 00 31 00 33 00 } //01 00 
		$a_01_1 = {02 9e 40 00 58 1f 40 00 10 f2 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 04 00 00 00 e9 00 00 00 88 15 40 00 80 14 40 00 3c 14 40 00 78 00 00 00 8a } //01 00 
		$a_01_2 = {6b 00 75 00 6e 00 6a 00 73 00 66 00 75 00 7a 00 6a 00 6e 00 73 00 64 00 6d 00 6d 00 78 00 7a 00 77 00 } //00 00 
	condition:
		any of ($a_*)
 
}