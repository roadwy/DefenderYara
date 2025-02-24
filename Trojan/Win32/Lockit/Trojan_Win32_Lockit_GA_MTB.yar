
rule Trojan_Win32_Lockit_GA_MTB{
	meta:
		description = "Trojan:Win32/Lockit.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {b8 0a 00 00 00 3b f0 0f 42 f0 8d 46 01 3d ff ff ff 7f 0f 87 c9 02 00 00 03 c0 3d 00 10 00 00 72 2f } //5
		$a_00_1 = {5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 69 00 } //1 \config.ini
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 44 6c 6c 33 5c 52 65 6c 65 61 73 65 5c 44 6c 6c 33 2e 70 64 62 } //1 C:\Users\Administrator\Desktop\Dll3\Release\Dll3.pdb
		$a_01_3 = {43 72 65 61 74 65 42 72 6f 77 73 65 72 } //1 CreateBrowser
		$a_00_4 = {5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 64 00 61 00 74 00 } //1 \config.dat
		$a_01_5 = {4c 6f 63 6b 69 74 } //1 Lockit
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}