
rule Trojan_Win32_Shelm_RB_MTB{
	meta:
		description = "Trojan:Win32/Shelm.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {53 53 6a 03 53 66 ab 6a 03 53 68 90 01 03 00 c7 45 ec 90 01 03 00 aa c7 45 f0 90 01 03 00 c7 45 f4 90 01 03 00 c7 45 f8 90 01 03 00 ff 15 90 00 } //01 00 
		$a_01_1 = {66 75 63 6b 69 6e 67 20 57 72 6f 6e 67 32 } //01 00  fucking Wrong2
		$a_01_2 = {52 65 76 65 72 73 65 20 53 68 65 6c 6c 20 45 72 72 6f 72 } //01 00  Reverse Shell Error
		$a_01_3 = {55 73 61 67 65 20 3a 20 25 73 20 49 50 20 50 6f 72 74 20 46 69 6c 65 4e 61 6d 65 20 3c 53 61 76 65 4e 61 6d 65 3e 20 2f 55 70 6c 6f 61 64 20 7c 20 2f 20 44 6f 77 6e 6c 6f 61 64 } //00 00  Usage : %s IP Port FileName <SaveName> /Upload | / Download
	condition:
		any of ($a_*)
 
}