
rule Ransom_Win32_Conti_RJ_MTB{
	meta:
		description = "Ransom:Win32/Conti.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b 73 74 72 69 6e 67 20 74 6f 6f 20 6c 6f 6e 67 } //01 00  expand 32-byte kexpand 16-byte kstring too long
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_2 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //01 00  @protonmail.com
		$a_01_3 = {69 70 68 6c 70 61 70 69 2e 70 64 62 } //01 00  iphlpapi.pdb
		$a_01_4 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 } //01 00  CryptImportKey
		$a_01_5 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //01 00  DecryptFileA
		$a_01_6 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //01 00  GetSystemInfo
		$a_01_7 = {56 00 6f 00 6c 00 75 00 6d 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 20 00 43 00 6f 00 70 00 79 00 } //00 00  Volume Shadow Copy
	condition:
		any of ($a_*)
 
}