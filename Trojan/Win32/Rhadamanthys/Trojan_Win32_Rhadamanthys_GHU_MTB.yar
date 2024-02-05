
rule Trojan_Win32_Rhadamanthys_GHU_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.GHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {64 00 6c 00 c7 05 90 01 04 32 00 2e 00 66 a3 90 01 04 c7 05 90 01 04 6d 00 73 00 66 89 0d 90 01 04 c7 05 90 01 04 67 00 33 00 ff 15 90 00 } //0a 00 
		$a_03_1 = {19 36 6b ff c7 05 90 01 08 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}