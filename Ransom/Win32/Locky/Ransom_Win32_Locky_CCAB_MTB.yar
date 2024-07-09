
rule Ransom_Win32_Locky_CCAB_MTB{
	meta:
		description = "Ransom:Win32/Locky.CCAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 6c 24 14 03 6c 24 08 8b 54 24 1c 03 54 24 04 8a 6d 00 8a 22 30 e5 88 6d 00 83 44 24 08 ?? ff 44 24 04 8b 5c 24 04 3b 5c 24 20 7e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}