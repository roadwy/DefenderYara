
rule Trojan_Win32_WhisperGate_ES_MTB{
	meta:
		description = "Trojan:Win32/WhisperGate.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {8d 0c 02 8b 55 f4 8b 45 08 01 d0 0f b6 18 8b 45 f4 99 f7 7d ec 89 d0 89 c2 8b 45 0c 01 d0 0f b6 00 31 d8 88 01 83 45 f4 01 } //10
		$a_01_1 = {8b 55 f4 8b 45 08 01 d0 8b 4d f4 8b 55 08 01 ca 0f b6 1a 8b 4d f0 8b 55 0c 01 ca 0f b6 12 31 da 88 10 } //10
		$a_01_2 = {74 65 6d 70 6b 65 79 } //1 tempkey
		$a_01_3 = {66 69 6c 65 6e 61 6d 65 2e 64 6c 6c } //1 filename.dll
		$a_01_4 = {66 69 6c 65 6e 61 6d 65 2e 65 78 65 } //1 filename.exe
		$a_01_5 = {53 68 65 6c 6c 63 6f 64 65 20 65 78 65 63 75 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Shellcode executed successfully
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}