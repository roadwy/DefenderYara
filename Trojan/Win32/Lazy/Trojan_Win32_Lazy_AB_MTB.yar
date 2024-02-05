
rule Trojan_Win32_Lazy_AB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {83 7c 24 60 10 8d 44 24 4c 0f 43 44 24 4c 8a 04 10 2a 04 91 88 44 24 13 3b de 73 2e 8a 4c 24 13 8d 43 01 89 44 24 38 83 fe 10 8d 44 24 28 0f 43 c7 88 0c 18 c6 44 18 01 00 8b 74 24 3c 8b 5c 24 38 8b 7c 24 28 } //00 00 
	condition:
		any of ($a_*)
 
}