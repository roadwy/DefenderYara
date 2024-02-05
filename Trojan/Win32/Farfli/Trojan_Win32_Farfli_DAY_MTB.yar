
rule Trojan_Win32_Farfli_DAY_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 89 55 f8 8b 55 0c 03 55 f0 8b 45 08 03 45 f8 8a 0a 32 08 8b 55 0c 03 55 f0 88 0a e9 } //01 00 
		$a_01_1 = {40 89 45 f4 8b 55 08 03 55 f8 8a 02 88 45 fc 8b 4d 08 03 4d f8 8b 55 08 03 55 f4 8a 02 88 01 8b 4d 08 03 4d f4 8a 55 fc 88 11 eb } //01 00 
		$a_01_2 = {55 8b ec 83 ec 0c c6 45 f4 4d c6 45 f5 61 c6 45 f6 72 c6 45 f7 6b c6 45 f8 54 c6 45 f9 69 c6 45 fa 6d c6 45 fb 65 c6 45 fc } //01 00 
		$a_01_3 = {43 64 65 66 67 68 69 6a 20 4c 6d 6e 6f 70 71 72 73 74 20 56 77 78 79 61 62 63 20 45 66 67 68 69 6a 6b 6c } //00 00 
	condition:
		any of ($a_*)
 
}