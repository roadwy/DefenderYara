
rule Trojan_Win32_Rhadamanthys_IKJ_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.IKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 51 03 c5 50 8d 54 24 90 01 01 52 89 4c 24 90 01 01 e8 90 01 04 2b 74 24 90 01 01 81 44 24 90 01 05 83 6c 24 90 01 02 89 74 24 90 01 01 0f 85 90 0a 42 00 01 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 4c 24 90 01 01 33 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}