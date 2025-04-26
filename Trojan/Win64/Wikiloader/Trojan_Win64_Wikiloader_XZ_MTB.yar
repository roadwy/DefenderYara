
rule Trojan_Win64_Wikiloader_XZ_MTB{
	meta:
		description = "Trojan:Win64/Wikiloader.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 d9 48 c7 c0 2f 00 00 00 48 83 c0 31 65 48 8b 18 48 c7 c0 10 00 00 00 48 83 c0 08 50 48 31 c0 48 ff c0 48 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}