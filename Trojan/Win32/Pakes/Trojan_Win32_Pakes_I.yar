
rule Trojan_Win32_Pakes_I{
	meta:
		description = "Trojan:Win32/Pakes.I,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 66 4c 6f 77 65 72 49 72 71 6c } //01 00  KfLowerIrql
		$a_00_1 = {4b 65 47 65 74 43 75 72 72 65 6e 74 49 72 71 6c } //01 00  KeGetCurrentIrql
		$a_00_2 = {5a 77 51 75 65 72 79 44 69 72 65 63 74 6f 72 79 46 69 6c 65 } //01 00  ZwQueryDirectoryFile
		$a_00_3 = {5a 77 43 72 65 61 74 65 46 69 6c 65 } //01 00  ZwCreateFile
		$a_00_4 = {5a 77 45 6e 75 6d 65 72 61 74 65 4b 65 79 } //01 00  ZwEnumerateKey
		$a_00_5 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_02_6 = {55 8b ec 51 56 8b 35 90 01 02 01 00 ff d6 ff d6 3a c3 73 0d 8a cb ff 15 90 01 02 01 00 88 90 01 02 eb 0d ff d6 8a cb 88 90 01 02 ff 15 90 01 02 01 00 8a 90 01 02 5e 90 00 } //01 00 
		$a_00_7 = {0f 20 c0 8b d8 81 e3 ff ff fe ff 0f 22 c3 } //01 00 
		$a_00_8 = {56 8b 34 81 80 3e e9 } //00 00 
	condition:
		any of ($a_*)
 
}