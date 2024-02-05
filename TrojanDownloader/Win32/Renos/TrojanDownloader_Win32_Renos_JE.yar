
rule TrojanDownloader_Win32_Renos_JE{
	meta:
		description = "TrojanDownloader:Win32/Renos.JE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 ff ff af 16 68 ff ff c9 4e e8 90 01 02 ff ff 68 ff ff 87 29 68 ff ff 1b f2 90 00 } //01 00 
		$a_01_1 = {03 00 42 00 49 00 4e 00 4d 5a 50 00 02 } //02 00 
		$a_00_2 = {03 00 42 00 49 00 4e 00 c2 d2 9c 7a 90 90 21 eb 83 a9 b1 b5 ad 38 e3 5d a8 4c b6 1f fb 3a 6a 63 ac 25 12 79 5e 44 ca aa 34 d6 35 24 d6 7f 8b 94 4b 88 25 08 c6 38 d4 72 65 33 dd de 1c 21 59 8f e3 } //00 00 
	condition:
		any of ($a_*)
 
}