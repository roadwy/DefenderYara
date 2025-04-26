
rule Trojan_Win32_DarkLoader_DF_MTB{
	meta:
		description = "Trojan:Win32/DarkLoader.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {41 6e 74 69 53 74 65 61 6c 65 72 42 79 44 61 72 6b } //AntiStealerByDark  3
		$a_80_1 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //gethostbyname  3
		$a_80_2 = {77 73 70 61 74 68 2e 70 68 70 77 73 70 61 74 68 2e 70 68 70 77 73 70 61 74 68 2e 70 68 70 77 73 70 61 74 68 2e 70 68 70 3f } //wspath.phpwspath.phpwspath.phpwspath.php?  3
		$a_80_3 = {77 73 6c 69 6e 6b 2e 70 68 70 3f } //wslink.php?  3
		$a_80_4 = {67 74 61 5f 73 61 5f 65 78 65 } //gta_sa_exe  3
		$a_80_5 = {41 73 68 6f 74 20 53 61 6d 70 } //Ashot Samp  3
		$a_80_6 = {64 61 72 6b 6c 6f 61 64 65 72 2e 72 75 } //darkloader.ru  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}