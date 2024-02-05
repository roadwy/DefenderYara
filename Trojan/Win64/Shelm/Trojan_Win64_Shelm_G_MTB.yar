
rule Trojan_Win64_Shelm_G_MTB{
	meta:
		description = "Trojan:Win64/Shelm.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f be 44 05 90 01 01 48 63 8d 64 01 00 00 0f be 8c 0d a4 00 00 00 33 90 01 01 48 63 8d 84 01 00 00 88 84 0d 90 01 04 8b 85 64 01 00 00 ff c0 89 85 64 01 00 00 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}