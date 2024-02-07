
rule Backdoor_WinNT_Farfli_A_sys{
	meta:
		description = "Backdoor:WinNT/Farfli.A!sys,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 01 00 "
		
	strings :
		$a_02_0 = {fa 8d 45 fc 50 e8 90 01 01 ff ff ff 8b 0d 90 01 02 01 00 a1 90 01 02 01 00 8b 51 01 8b 30 8b 14 96 89 15 90 01 02 01 00 8b 49 01 8b 00 c7 04 88 90 01 02 01 00 ff 75 fc e8 90 01 01 ff ff ff fb 90 00 } //01 00 
		$a_02_1 = {8d 45 e8 68 00 80 00 00 50 6a 04 57 ff 15 90 01 02 01 00 85 c0 7c 90 01 01 8d 45 e0 68 90 01 02 01 00 50 ff d6 8d 45 e8 50 8d 45 e0 50 ff 15 90 01 02 01 00 8b f0 85 f6 7d 0d ff 75 fc ff 15 90 00 } //01 00 
		$a_02_2 = {8d 45 e8 68 00 80 00 00 50 6a 04 90 02 03 ff 15 90 01 02 01 00 3b 90 01 01 7c 90 01 01 8d 45 e0 68 90 01 02 01 00 50 ff 90 01 01 8d 45 e8 50 8d 45 e0 50 ff 15 90 01 02 01 00 8b 90 01 01 3b 90 01 01 7d 0d ff 75 fc ff 15 90 00 } //01 00 
		$a_01_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_01_4 = {5a 77 53 65 74 56 61 6c 75 65 4b 65 79 } //01 00  ZwSetValueKey
		$a_01_5 = {4f 62 52 65 66 65 72 65 6e 63 65 4f 62 6a 65 63 74 42 79 48 61 6e 64 6c 65 } //01 00  ObReferenceObjectByHandle
		$a_01_6 = {4f 62 66 44 65 72 65 66 65 72 65 6e 63 65 4f 62 6a 65 63 74 } //01 00  ObfDereferenceObject
		$a_01_7 = {5a 77 44 65 6c 65 74 65 56 61 6c 75 65 4b 65 79 } //01 00  ZwDeleteValueKey
		$a_01_8 = {5a 77 57 72 69 74 65 46 69 6c 65 } //00 00  ZwWriteFile
	condition:
		any of ($a_*)
 
}