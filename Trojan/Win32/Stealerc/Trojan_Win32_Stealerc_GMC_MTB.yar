
rule Trojan_Win32_Stealerc_GMC_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b f8 8a 15 90 01 04 83 c4 0c 69 c9 90 01 04 80 ea 60 80 f2 d1 88 0d 90 01 04 85 ff 74 90 01 01 8a c2 80 e9 48 80 ca 75 88 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}