
rule Trojan_Win32_Azorult_CM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.CM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {c7 45 f8 02 00 00 00 83 45 f8 03 8b 8d 24 fd ff ff 8b c3 c1 e0 04 89 85 2c fd ff ff 8d 85 2c fd ff ff } //05 00 
		$a_01_1 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3 01 08 c3 } //00 00 
	condition:
		any of ($a_*)
 
}