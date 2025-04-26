
rule Trojan_BAT_Razy_AR_MTB{
	meta:
		description = "Trojan:BAT/Razy.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 05 9a 0c 28 53 00 00 0a 08 6f 55 00 00 0a 0d 08 72 f7 00 00 70 6f 56 00 00 0a 08 72 0b 01 00 70 6f 56 00 00 0a 60 2d 47 02 7b 0b 00 00 04 28 57 00 00 0a 08 28 58 00 00 0a 18 18 73 59 00 00 0a 13 04 09 11 04 6f 5a 00 00 0a de 0c 11 04 2c 07 11 04 } //2
		$a_01_1 = {42 00 6c 00 61 00 63 00 6b 00 42 00 69 00 6e 00 64 00 65 00 72 00 53 00 74 00 75 00 62 00 2e 00 65 00 78 00 65 00 } //1 BlackBinderStub.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}