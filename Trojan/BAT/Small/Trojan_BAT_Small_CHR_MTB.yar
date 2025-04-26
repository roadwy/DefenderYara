
rule Trojan_BAT_Small_CHR_MTB{
	meta:
		description = "Trojan:BAT/Small.CHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 0f 00 06 00 00 "
		
	strings :
		$a_02_0 = {0a 0a 06 72 55 ?? ?? 70 6f ?? ?? ?? 0a 0b 07 0c 72 ?? ?? ?? 70 0d 00 73 ?? ?? ?? 0a 13 04 } //10
		$a_80_1 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 } //CreateDirectory  3
		$a_80_2 = {5c 4d 79 54 65 6d 70 5c 53 65 74 75 70 } //\MyTemp\Setup  3
		$a_80_3 = {57 65 62 43 6c 69 65 6e 74 } //WebClient  3
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  3
		$a_80_5 = {5a 32 6b 2f 53 65 72 76 65 72 } //Z2k/Server  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=15
 
}