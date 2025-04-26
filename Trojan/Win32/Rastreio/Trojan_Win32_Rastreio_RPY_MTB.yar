
rule Trojan_Win32_Rastreio_RPY_MTB{
	meta:
		description = "Trojan:Win32/Rastreio.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {51 00 47 00 56 00 6a 00 61 00 47 00 38 00 67 00 62 00 32 00 5a 00 6d 00 44 00 51 00 70 00 7a 00 5a 00 58 00 52 00 73 00 62 00 32 00 4e 00 68 00 62 00 43 00 42 00 46 00 62 00 6d 00 46 00 69 00 62 00 47 00 56 00 45 00 5a 00 57 00 78 00 68 00 65 00 57 00 56 00 6b 00 52 00 58 00 68 00 77 00 59 00 57 00 35 00 7a 00 61 00 57 00 39 00 75 00 44 00 51 00 70 00 6a 00 } //1 QGVjaG8gb2ZmDQpzZXRsb2NhbCBFbmFibGVEZWxheWVkRXhwYW5zaW9uDQpj
		$a_01_1 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //1 unknowndll.pdb
		$a_01_2 = {2e 00 62 00 61 00 74 00 } //1 .bat
		$a_01_3 = {55 6e 69 6d 70 6c 65 6d 65 6e 74 65 64 41 50 49 } //1 UnimplementedAPI
		$a_01_4 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 DllCanUnloadNow
		$a_01_5 = {25 6c 73 3d 25 6c 73 } //1 %ls=%ls
		$a_01_6 = {5b 52 65 6e 61 6d 65 5d } //1 [Rename]
		$a_01_7 = {45 00 78 00 65 00 63 00 53 00 68 00 65 00 6c 00 6c 00 3a 00 } //1 ExecShell:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}