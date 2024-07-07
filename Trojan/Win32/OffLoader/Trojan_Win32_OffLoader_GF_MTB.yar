
rule Trojan_Win32_OffLoader_GF_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 73 64 66 77 73 64 66 73 36 64 66 } //1 Software\sdfwsdfs6df
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 53 50 6f 6c 6f 43 6c 65 61 6e 65 72 } //1 Software\SPoloCleaner
		$a_81_2 = {70 65 61 63 65 73 6c 65 65 70 2e 73 69 74 65 2f 64 75 62 2e 70 68 70 3f 66 7a } //1 peacesleep.site/dub.php?fz
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}