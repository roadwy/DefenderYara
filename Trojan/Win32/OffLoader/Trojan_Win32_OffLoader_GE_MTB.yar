
rule Trojan_Win32_OffLoader_GE_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {53 4f 46 54 57 41 52 45 5c 59 43 4c } //1 SOFTWARE\YCL
		$a_81_1 = {67 6c 6f 76 65 66 69 72 65 2e 73 69 74 65 2f 64 75 62 2e 70 68 70 3f 66 7a } //1 glovefire.site/dub.php?fz
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}