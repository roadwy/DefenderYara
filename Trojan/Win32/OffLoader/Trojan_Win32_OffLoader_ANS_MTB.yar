
rule Trojan_Win32_OffLoader_ANS_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ANS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 00 61 00 62 00 62 00 69 00 74 00 73 00 77 00 65 00 65 00 6b 00 2e 00 69 00 63 00 75 00 2f 00 62 00 69 00 6b 00 2e 00 70 00 68 00 70 00 3f 00 } //3 rabbitsweek.icu/bik.php?
		$a_01_1 = {66 00 61 00 63 00 74 00 6c 00 6f 00 77 00 2e 00 78 00 79 00 7a 00 2f 00 62 00 69 00 6b 00 73 00 2e 00 70 00 68 00 70 00 3f 00 } //3 factlow.xyz/biks.php?
		$a_01_2 = {6e 00 6f 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //1 nocookies
		$a_01_3 = {44 00 6f 00 20 00 79 00 6f 00 75 00 20 00 77 00 61 00 6e 00 74 00 20 00 74 00 6f 00 20 00 72 00 65 00 62 00 6f 00 6f 00 74 00 20 00 6e 00 6f 00 77 00 3f 00 } //1 Do you want to reboot now?
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}