
rule Trojan_Linux_Getshell_D_MTB{
	meta:
		description = "Trojan:Linux/Getshell.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {21 e0 99 03 d0 ff bd 27 2c 00 bf af 28 00 b4 af 24 00 b3 af 20 00 b2 af 1c 00 b1 af 18 00 b0 af 10 00 bc af b4 80 99 8f 18 80 92 8f 09 f8 20 03 01 00 11 24 } //1
		$a_01_1 = {fb ff 02 24 24 10 02 01 00 0f e3 30 25 10 43 00 01 00 05 24 14 00 a4 ae 10 00 a2 ae 1c 00 a5 ae 00 00 c2 80 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}