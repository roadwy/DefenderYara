
rule Trojan_Win32_CryptInject_SF_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.SF!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 30 31 5f 46 47 5c 30 32 5f 73 65 6c 66 70 72 6f 6a 65 63 74 5c 30 31 5f 72 75 6e 74 61 73 6b 5c 30 31 5f 6d 69 61 6e 73 68 61 5c 4d 79 4a 69 61 6b 65 32 2d 64 65 73 74 5c 52 65 6c 65 61 73 65 5c 4d 79 4a 69 61 6b 65 2e 70 64 62 } //1 F:\01_FG\02_selfproject\01_runtask\01_miansha\MyJiake2-dest\Release\MyJiake.pdb
		$a_01_1 = {43 00 3a 00 5c 00 49 00 4e 00 54 00 45 00 52 00 4e 00 41 00 4c 00 5c 00 52 00 45 00 4d 00 4f 00 54 00 45 00 2e 00 45 00 58 00 45 00 } //1 C:\INTERNAL\REMOTE.EXE
		$a_01_2 = {53 00 68 00 61 00 64 00 6f 00 77 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //1 Shadow Defender\Service.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}