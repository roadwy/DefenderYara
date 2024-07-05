
rule Trojan_Win64_CryptInject_GIF_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 44 02 d9 44 02 df 41 0f b6 d3 41 8a 04 94 41 30 07 41 8b 04 94 49 ff c7 41 31 04 9c 43 8b 04 ac 41 8d 14 00 43 31 14 94 48 ff 4c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}