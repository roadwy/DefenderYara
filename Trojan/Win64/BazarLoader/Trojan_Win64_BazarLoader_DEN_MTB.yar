
rule Trojan_Win64_BazarLoader_DEN_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.DEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {c1 c0 07 48 8d 52 01 0f be c9 33 c1 0f b6 0a 84 c9 75 ed } //03 00 
		$a_81_1 = {6c 77 74 7a 72 76 7a 62 69 68 76 74 2e 64 6c 6c } //00 00  lwtzrvzbihvt.dll
	condition:
		any of ($a_*)
 
}