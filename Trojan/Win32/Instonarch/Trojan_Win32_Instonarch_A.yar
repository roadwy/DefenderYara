
rule Trojan_Win32_Instonarch_A{
	meta:
		description = "Trojan:Win32/Instonarch.A,SIGNATURE_TYPE_PEHSTR_EXT,3e 00 3e 00 07 00 00 "
		
	strings :
		$a_00_0 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d 20 76 } //10 Nullsoft Install System v
		$a_00_1 = {5c 52 65 67 69 73 74 72 79 2e 64 6c 6c } //10 \Registry.dll
		$a_00_2 = {5c 69 6e 65 74 63 2e 64 6c 6c } //10 \inetc.dll
		$a_00_3 = {77 77 77 2e 69 6e 73 74 61 6c 6c 6d 6f 6e 65 74 69 7a 65 72 2e 63 6f 6d } //10 www.installmonetizer.com
		$a_00_4 = {2f 53 49 4c 45 4e 54 } //10 /SILENT
		$a_02_5 = {69 74 65 6d 69 64 3d [0-02] 26 70 75 62 69 64 3d } //10
		$a_00_6 = {2f 74 72 61 63 6b 73 74 61 74 73 2e 70 68 70 } //2 /trackstats.php
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_02_5  & 1)*10+(#a_00_6  & 1)*2) >=62
 
}