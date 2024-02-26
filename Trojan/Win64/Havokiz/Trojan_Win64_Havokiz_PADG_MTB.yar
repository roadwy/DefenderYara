
rule Trojan_Win64_Havokiz_PADG_MTB{
	meta:
		description = "Trojan:Win64/Havokiz.PADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 83 fb 0f 48 0f 47 cf 33 d2 48 f7 f6 44 32 04 0a 45 88 01 41 ff c2 4d 8d 49 01 49 63 c2 48 3b 90 01 05 72 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}