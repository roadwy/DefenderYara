
rule Trojan_BAT_Disco_GNW_MTB{
	meta:
		description = "Trojan:BAT/Disco.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {0b 07 17 2e 08 07 20 01 80 ff ff 33 23 7e 01 00 00 04 06 0c 12 02 fe } //5
		$a_01_1 = {80 01 00 00 04 06 17 58 0a 06 20 ff 00 00 00 32 be } //5
		$a_80_2 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 36 31 39 30 35 37 33 36 31 33 39 35 35 34 38 37 36 } //cdn.discordapp.com/attachments/961905736139554876  1
		$a_80_3 = {73 74 61 72 74 6b 65 79 6c 6f 67 67 65 72 } //startkeylogger  1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=12
 
}