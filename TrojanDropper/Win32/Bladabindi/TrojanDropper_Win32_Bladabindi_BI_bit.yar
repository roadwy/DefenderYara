
rule TrojanDropper_Win32_Bladabindi_BI_bit{
	meta:
		description = "TrojanDropper:Win32/Bladabindi.BI!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a 44 6f 0d 0a 57 53 63 72 69 70 74 2e 73 6c 65 65 70 20 90 02 10 2e 73 65 6e 64 6b 65 79 73 22 7b 6e 75 6d 6c 6f 63 6b 7d 22 0d 0a 57 53 63 72 69 70 74 2e 73 6c 65 65 70 20 90 02 10 2e 73 65 6e 64 6b 65 79 73 22 7b 63 61 70 73 6c 6f 63 6b 7d 22 0d 0a 57 53 63 72 69 70 74 2e 73 6c 65 65 70 20 90 02 10 2e 73 65 6e 64 6b 65 79 73 22 7b 73 63 72 6f 6c 6c 6c 6f 63 6b 7d 22 0d 0a 57 53 63 72 69 70 74 2e 73 6c 65 65 70 90 02 08 4c 6f 6f 70 90 00 } //1
		$a_01_1 = {53 65 72 76 65 72 2e 73 66 78 2e 65 78 65 } //1 Server.sfx.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}