
rule Trojan_BAT_Rozena_AYA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 1e 5d 1f 1f 5f 63 02 07 91 1e 03 1e 5d 59 1f 1f 5f 62 60 d2 9c 06 07 8f 01 00 00 01 25 47 04 07 20 00 01 00 00 5d 61 d2 61 d2 52 06 07 06 07 91 07 20 80 00 00 00 5d 59 20 ff 00 00 00 5f d2 9c 07 17 58 0b 07 02 8e 69 3f ad ff ff ff } //7
		$a_01_1 = {4e 6f 41 6e 61 6c 79 73 69 73 } //2 NoAnalysis
		$a_01_2 = {73 74 65 61 6c 74 68 2e 65 78 65 } //1 stealth.exe
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=10
 
}