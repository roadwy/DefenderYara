
rule Ransom_Win32_AnteFrigus_SK_MTB{
	meta:
		description = "Ransom:Win32/AnteFrigus.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 74 68 65 73 65 20 61 63 74 69 6f 6e 73 20 77 69 6c 6c 20 6c 65 61 64 20 74 6f 20 64 61 74 61 20 6c 6f 73 73 20 61 6e 64 20 75 6e 72 65 63 6f 76 65 72 61 62 6c 65 2e } //01 00  All these actions will lead to data loss and unrecoverable.
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 6f 6e 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 64 75 65 20 74 6f 20 73 65 63 75 72 69 74 79 20 69 73 73 75 65 73 2e } //01 00  Your files on this computer have been encrypted due to security issues.
		$a_01_2 = {54 6f 20 64 65 63 72 79 70 74 20 66 69 6c 65 73 20 66 6f 6c 6c 6f 77 20 74 68 65 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 20 62 65 6c 6f 77 3a } //05 00  To decrypt files follow the instructions below:
		$a_01_3 = {77 6d 69 63 2e 65 78 65 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //05 00  wmic.exe shadowcopy delete
		$a_01_4 = {2d 20 70 65 72 73 6f 6e 61 6c 20 6b 65 79 3a } //00 00  - personal key:
		$a_00_5 = {5d 04 00 00 c9 34 04 80 5c 25 00 } //00 ca 
	condition:
		any of ($a_*)
 
}