
rule Trojan_Win32_Guloader_CG_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 80 b3 59 85 b6 5f 8a b9 66 8f bc 6d 94 bf 73 99 c2 79 } //01 00 
		$a_01_1 = {55 82 b4 5b 87 b7 62 8b ba 68 90 bd 6d 94 c1 73 98 c4 79 } //00 00 
	condition:
		any of ($a_*)
 
}