
rule Trojan_Win32_Matcash_gen_C{
	meta:
		description = "Trojan:Win32/Matcash.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 7b 46 39 43 44 38 35 34 42 2d 32 43 38 42 2d 34 31 32 66 2d 38 46 31 33 2d 42 30 42 46 38 44 44 45 42 32 32 39 7d } //10 Global\{F9CD854B-2C8B-412f-8F13-B0BF8DDEB229}
		$a_01_1 = {2f 77 74 64 2e 70 68 70 3f 75 69 64 3d 7b } //10 /wtd.php?uid={
		$a_01_2 = {49 6d 70 6f 73 73 69 62 6c 65 20 64 65 20 6c 69 72 65 20 6c 65 20 66 69 63 68 69 65 72 20 64 65 20 73 6f 72 74 69 65 } //3 Impossible de lire le fichier de sortie
		$a_01_3 = {6d 63 62 6f 6f 2e 63 6f 6d } //3 mcboo.com
		$a_01_4 = {6d 63 2d 00 } //3 捭-
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 43 4c 53 49 44 5c 7b } //1 Software\Classes\CLSID\{
		$a_01_6 = {53 79 73 74 65 6d 42 69 6f 73 44 61 74 65 } //1 SystemBiosDate
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=25
 
}