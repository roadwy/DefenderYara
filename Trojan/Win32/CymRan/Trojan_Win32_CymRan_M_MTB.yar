
rule Trojan_Win32_CymRan_M_MTB{
	meta:
		description = "Trojan:Win32/CymRan.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 79 6d 75 6c 61 74 65 4e 61 74 69 76 65 52 61 6e 73 6f 6d 77 61 72 65 47 65 6e 65 72 61 74 65 64 4b 65 79 } //1 CymulateNativeRansomwareGeneratedKey
		$a_01_1 = {70 72 6f 67 72 61 6d 64 61 74 61 5c 43 79 6d 75 6c 61 74 65 } //1 programdata\Cymulate
		$a_01_2 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //1 EncryptedFiles
		$a_01_3 = {45 44 52 5f 61 74 74 61 63 6b 73 5f 70 61 74 68 } //1 EDR_attacks_path
		$a_01_4 = {41 74 74 61 63 6b 73 4c 6f 67 73 5c 65 64 72 } //1 AttacksLogs\edr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}