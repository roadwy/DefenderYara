
rule Backdoor_WinNT_Farfli_A_sys{
	meta:
		description = "Backdoor:WinNT/Farfli.A!sys,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_02_0 = {fa 8d 45 fc 50 e8 ?? ff ff ff 8b 0d ?? ?? 01 00 a1 ?? ?? 01 00 8b 51 01 8b 30 8b 14 96 89 15 ?? ?? 01 00 8b 49 01 8b 00 c7 04 88 ?? ?? 01 00 ff 75 fc e8 ?? ff ff ff fb } //1
		$a_02_1 = {8d 45 e8 68 00 80 00 00 50 6a 04 57 ff 15 ?? ?? 01 00 85 c0 7c ?? 8d 45 e0 68 ?? ?? 01 00 50 ff d6 8d 45 e8 50 8d 45 e0 50 ff 15 ?? ?? 01 00 8b f0 85 f6 7d 0d ff 75 fc ff 15 } //1
		$a_02_2 = {8d 45 e8 68 00 80 00 00 50 6a 04 [0-03] ff 15 ?? ?? 01 00 3b ?? 7c ?? 8d 45 e0 68 ?? ?? 01 00 50 ff ?? 8d 45 e8 50 8d 45 e0 50 ff 15 ?? ?? 01 00 8b ?? 3b ?? 7d 0d ff 75 fc ff 15 } //1
		$a_01_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_01_4 = {5a 77 53 65 74 56 61 6c 75 65 4b 65 79 } //1 ZwSetValueKey
		$a_01_5 = {4f 62 52 65 66 65 72 65 6e 63 65 4f 62 6a 65 63 74 42 79 48 61 6e 64 6c 65 } //1 ObReferenceObjectByHandle
		$a_01_6 = {4f 62 66 44 65 72 65 66 65 72 65 6e 63 65 4f 62 6a 65 63 74 } //1 ObfDereferenceObject
		$a_01_7 = {5a 77 44 65 6c 65 74 65 56 61 6c 75 65 4b 65 79 } //1 ZwDeleteValueKey
		$a_01_8 = {5a 77 57 72 69 74 65 46 69 6c 65 } //1 ZwWriteFile
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}