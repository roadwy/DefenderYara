
rule Trojan_Win32_Azorult_RPE_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e1 04 03 cb 33 4d 08 33 4d 0c 2b f1 89 4d 08 89 75 e8 8b 45 e8 03 45 f4 89 45 0c } //01 00 
		$a_01_1 = {89 45 08 8b 45 e4 01 45 08 ff 75 08 8b c6 c1 e0 04 03 45 e0 33 45 0c 89 45 fc 8d 45 fc 50 } //00 00 
	condition:
		any of ($a_*)
 
}