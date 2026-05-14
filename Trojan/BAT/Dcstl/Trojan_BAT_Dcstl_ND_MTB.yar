
rule Trojan_BAT_Dcstl_ND_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 2d 75 1b 8d a1 00 00 01 25 16 72 99 1b 00 70 07 28 59 00 00 0a a2 25 17 72 c1 1b 00 70 07 28 59 00 00 0a a2 25 18 07 a2 25 19 72 d7 1b 00 70 07 28 59 00 00 0a a2 25 1a 07 25 2d 06 26 72 eb 1b 00 70 a2 13 0b 16 13 0c 2b 25 11 0b 11 0c 9a 13 0e 11 09 11 0e 6f c3 00 00 0a } //2
		$a_01_1 = {54 65 73 74 2d 42 6f 74 2e 64 6c 6c } //1 Test-Bot.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}