
rule Trojan_Win32_Vundo_gen_E{
	meta:
		description = "Trojan:Win32/Vundo.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 10 8b 75 0c 59 33 c9 85 db 89 45 fc 76 12 33 d2 8b c1 f7 75 fc 8a 04 3a 30 04 31 41 3b cb 72 ee 5f c6 04 1e 00 } //1
		$a_03_1 = {3b c6 59 76 6d 8d 85 ?? ?? ff ff 48 48 89 85 ?? ?? ff ff eb 06 8b 85 ?? ?? ff ff 8d 7e 01 80 3c 38 3b 75 3b 2b f3 56 8d } //1
		$a_03_2 = {3b c6 59 76 74 8d 85 ?? ?? ff ff 48 48 89 85 ?? ?? ff ff eb 06 8b 85 ?? ?? ff ff 8d 5e 01 80 3c 18 3b 75 3b 2b f7 56 8d } //1
		$a_03_3 = {6a 4e 56 ff 15 ?? ?? ?? ?? 83 f8 ff 74 3a 53 8d 85 ?? ?? ff ff 50 6a 0d 8d 45 ec 50 56 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}