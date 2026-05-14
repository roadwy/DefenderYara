
rule Trojan_BAT_Jalapeno_AMTB{
	meta:
		description = "Trojan:BAT/Jalapeno!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 31 35 35 2e 31 31 37 2e 34 30 2e 32 32 31 2f } //http://155.117.40.221/  2
		$a_80_1 = {78 68 73 71 69 67 62 34 2e 69 6f 70 2e 65 78 65 } //xhsqigb4.iop.exe  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}
rule Trojan_BAT_Jalapeno_AMTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 80 01 00 00 04 72 5f 00 00 70 80 02 00 00 04 2a } //2
		$a_01_1 = {28 05 00 00 0a 0a 16 0b 2b 23 06 07 9a 0c 08 6f 06 00 00 0a 02 1b 6f 07 00 00 0a 2c 0c 08 6f 08 00 00 0a 6f 09 00 00 0a 2a 07 17 58 0b 07 06 8e 69 32 d7 14 2a } //2
		$a_01_2 = {12 00 28 0a 00 00 0a 7d 0d 00 00 04 12 00 15 7d 0c 00 00 04 12 00 7c 0d 00 00 04 12 00 28 02 00 00 2b 12 00 7c 0d 00 00 04 28 0c 00 00 0a 2a } //2
		$a_80_3 = {41 64 6d 69 6e 49 64 } //AdminId  2
		$a_80_4 = {42 6f 74 54 6f 6b 65 6e } //BotToken  2
		$a_80_5 = {75 73 65 72 49 70 } //userIp  2
		$a_80_6 = {70 65 72 65 64 6f 7a 2e 64 6c 6c } //peredoz.dll  2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2) >=14
 
}