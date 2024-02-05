
rule Trojan_Win64_DllHijack_DA_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 8b 45 08 48 8d 50 f0 48 39 ca 76 90 01 01 48 89 c8 31 d2 4c 8b 4c 24 40 48 f7 74 24 48 49 8b 45 00 41 8a 14 11 32 54 08 10 89 c8 41 0f af c0 31 c2 88 14 0b 48 ff c1 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}