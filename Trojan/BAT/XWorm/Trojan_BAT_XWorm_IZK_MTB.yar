
rule Trojan_BAT_XWorm_IZK_MTB{
	meta:
		description = "Trojan:BAT/XWorm.IZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 5c 00 00 0a 06 07 16 07 8e b7 6f 5c 00 00 0a 7e 10 00 00 04 15 17 6f 63 00 00 0a 26 7e 10 00 00 04 06 6f 58 00 00 0a 16 06 6f 5d 00 00 0a b7 16 14 fe 06 1d 00 00 06 73 48 00 00 0a 14 6f 64 00 00 0a } //3
		$a_00_1 = {52 00 75 00 6e 00 42 00 6f 00 74 00 4b 00 69 00 6c 00 6c 00 65 00 72 00 } //1 RunBotKiller
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*1) >=4
 
}