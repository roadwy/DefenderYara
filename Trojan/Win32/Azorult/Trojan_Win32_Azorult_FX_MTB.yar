
rule Trojan_Win32_Azorult_FX_MTB{
	meta:
		description = "Trojan:Win32/Azorult.FX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 0c be 90 01 04 57 57 57 57 57 57 ff 15 90 01 04 4e 75 f1 e8 07 00 00 00 5f 33 c0 5e c2 10 00 90 00 } //01 00 
		$a_02_1 = {7c df c7 45 90 01 05 c7 45 90 01 05 c7 45 90 01 05 90 0a 50 00 00 8b f3 05 90 01 04 a3 90 01 03 00 81 fe 90 01 03 00 75 10 68 90 01 03 00 ff 15 90 01 03 00 a3 90 01 03 00 46 81 fe 90 01 03 00 7c df c7 45 90 01 05 c7 45 90 01 05 c7 45 90 01 05 c7 45 90 01 05 c7 45 90 01 05 c7 45 90 01 05 c7 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}