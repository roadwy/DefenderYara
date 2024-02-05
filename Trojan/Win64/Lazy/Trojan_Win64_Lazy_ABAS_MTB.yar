
rule Trojan_Win64_Lazy_ABAS_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ABAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {f3 0f 7f 45 97 48 89 4d 2f c7 45 a7 c0 cf 86 c9 c7 45 ab c4 c1 c0 cd c7 45 af c0 c2 d5 00 c6 45 b3 01 0f 1f 40 00 66 66 0f 1f 84 00 00 00 00 00 8d 41 97 30 44 0d 97 48 ff c1 48 83 f9 1b 72 f0 } //00 00 
	condition:
		any of ($a_*)
 
}