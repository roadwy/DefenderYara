
rule TrojanSpy_BAT_Stealergen_MR_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {8e 69 1e 5a 6f ?? ?? ?? 0a 00 08 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 08 02 7b ?? ?? ?? 04 8e 69 1e 5a 6f ?? ?? ?? 0a 00 08 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 0d } //1
		$a_03_1 = {03 8e 69 17 59 17 58 8d ?? ?? ?? 01 13 06 11 05 11 06 16 03 8e 69 6f ?? ?? ?? 0a 13 07 11 06 11 07 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 08 de } //1
		$a_01_2 = {63 00 69 00 70 00 68 00 65 00 72 00 } //1 cipher
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_6 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_7 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
		$a_01_8 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_9 = {56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 41 74 74 61 63 68 } //1 VirtualMachineRemoteDebuggerAttach
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}