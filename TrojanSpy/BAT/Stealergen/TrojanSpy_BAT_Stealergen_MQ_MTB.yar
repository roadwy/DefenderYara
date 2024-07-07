
rule TrojanSpy_BAT_Stealergen_MQ_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {39 35 31 30 30 36 61 37 2d 62 30 32 66 2d 34 33 62 30 2d 39 33 31 33 2d 66 39 34 38 66 32 38 61 62 35 66 61 } //1 951006a7-b02f-43b0-9313-f948f28ab5fa
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_2 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 30 37 2d 31 } //1 $$method0x6000007-1
		$a_01_3 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 32 61 2d 31 } //1 $$method0x600002a-1
		$a_01_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_5 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_6 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
		$a_01_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_8 = {73 65 74 5f 4b 65 79 } //1 set_Key
		$a_01_9 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_10 = {49 73 4b 65 79 4c 6f 63 6b 65 64 } //1 IsKeyLocked
		$a_01_11 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}