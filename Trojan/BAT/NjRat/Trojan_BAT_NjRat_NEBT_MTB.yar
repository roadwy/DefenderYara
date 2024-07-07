
rule Trojan_BAT_NjRat_NEBT_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {04 16 0a 2b 1b 00 7e 90 01 01 00 00 04 06 7e 90 01 01 00 00 04 06 91 20 90 01 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 90 01 01 00 00 04 8e 69 fe 04 0b 07 2d d7 7e 90 01 01 00 00 04 0c 2b 00 08 2a 90 00 } //10
		$a_01_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 } //2 cdn.discordapp.com/attachments
		$a_01_2 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //2 Form1_Load
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}