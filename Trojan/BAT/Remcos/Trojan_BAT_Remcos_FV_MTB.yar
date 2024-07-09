
rule Trojan_BAT_Remcos_FV_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 1b 00 7e ?? ?? ?? 04 06 7e ?? ?? ?? 04 06 91 20 74 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? ?? ?? 04 8e 69 fe 04 0b 07 2d d7 } //1
		$a_81_1 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //1 cdn.discordapp.com/attachments/
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}