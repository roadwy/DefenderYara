
rule TrojanDownloader_BAT_QuasarRAT_M_MTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00 20 00 65 00 6c 00 65 00 76 00 61 00 74 00 65 00 64 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 70 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 } //2 Successfully elevated process privilege
		$a_01_1 = {2f 00 44 00 72 00 6f 00 70 00 70 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //2 /Dropper.exe
		$a_01_2 = {43 00 3a 00 5c 00 73 00 6b 00 6f 00 70 00 5c 00 6b 00 75 00 72 00 61 00 63 00 2e 00 65 00 78 00 65 00 } //2 C:\skop\kurac.exe
		$a_01_3 = {43 00 3a 00 5c 00 73 00 6b 00 6f 00 70 00 5c 00 6d 00 63 00 6b 00 78 00 2e 00 65 00 78 00 65 00 } //2 C:\skop\mckx.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}