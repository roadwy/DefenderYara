
rule Trojan_Win32_Zenpak_T_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 30 ba 02 00 00 00 8d 05 90 01 04 01 18 89 c2 83 c2 09 83 ea 05 8d 05 90 01 04 31 38 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}