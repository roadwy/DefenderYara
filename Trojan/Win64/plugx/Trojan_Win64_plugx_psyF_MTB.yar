
rule Trojan_Win64_plugx_psyF_MTB{
	meta:
		description = "Trojan:Win64/plugx.psyF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {85 c9 76 74 48 8b 4c 24 68 48 89 4c 24 70 48 8d 05 5b 6e 00 00 e8 76 de f9 ff 48 8b 4c 24 58 48 89 08 48 8b 54 24 70 48 89 50 08 48 8b 54 24 48 } //00 00 
	condition:
		any of ($a_*)
 
}