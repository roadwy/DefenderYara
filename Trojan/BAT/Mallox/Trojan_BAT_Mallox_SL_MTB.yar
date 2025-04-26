
rule Trojan_BAT_Mallox_SL_MTB{
	meta:
		description = "Trojan:BAT/Mallox.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {d0 93 00 00 06 26 1f 0d 13 0e 2b a5 02 20 3f 9e dc 7c 61 03 61 0a 7e 59 00 00 04 0c 08 74 08 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 1f 0c 13 0e 38 7b ff ff ff } //2
		$a_81_1 = {72 76 61 68 74 2e 65 78 65 } //2 rvaht.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}