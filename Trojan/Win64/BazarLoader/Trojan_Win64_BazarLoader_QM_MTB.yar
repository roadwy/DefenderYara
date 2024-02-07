
rule Trojan_Win64_BazarLoader_QM_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {b8 01 00 00 00 83 c0 00 eb 00 48 83 c4 18 c3 48 89 4c 24 08 48 83 ec 18 eb 00 8b 44 24 28 89 04 24 eb dd 44 89 4c 24 20 4c 89 44 24 18 eb 0b } //03 00 
		$a_81_1 = {76 45 34 48 50 4e 51 44 63 57 31 71 52 6f } //03 00  vE4HPNQDcW1qRo
		$a_81_2 = {61 78 36 34 2e 64 6c 6c } //00 00  ax64.dll
	condition:
		any of ($a_*)
 
}