
rule TrojanSpy_Win32_Banker_VAY{
	meta:
		description = "TrojanSpy:Win32/Banker.VAY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 } //3
		$a_00_1 = {2a 3a 45 6e 61 62 6c 65 64 3a 6d 73 61 70 70 74 73 33 32 2e 65 78 65 } //1 *:Enabled:msappts32.exe
		$a_00_2 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 77 70 6c 6f 67 73 2e 74 78 74 } //1 C:\windows\wplogs.txt
		$a_00_3 = {64 65 6c 65 78 65 63 2e 62 61 74 } //1 delexec.bat
		$a_00_4 = {43 68 61 76 65 20 50 72 69 6d df 72 69 61 20 49 6e 76 df 6c 69 64 61 20 21 } //1
		$a_00_5 = {45 6e 76 69 61 6e 64 6f 20 53 50 61 6d } //1 Enviando SPam
		$a_00_6 = {43 6f 6e 74 61 20 70 61 64 72 61 6f 20 4f 75 74 6c 6f 6f 6f 6b 20 3a } //1 Conta padrao Outloook :
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}