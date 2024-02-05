
rule Trojan_Win64_BazarLoader_AA_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f be 84 0c 90 01 04 83 e8 90 02 04 6b c0 d4 99 41 f7 f8 8d 42 90 01 01 99 41 f7 f8 88 94 0c 90 01 04 48 ff c1 48 83 f9 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}