
rule Trojan_Win32_Xpack_RPY_MTB{
	meta:
		description = "Trojan:Win32/Xpack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 b9 0a 00 00 00 8b 04 9e f7 f1 88 15 90 01 04 89 04 9f 4b 59 49 75 e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}