
rule Trojan_Win32_CerberCrypt_D_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b f8 90 8b df } //2
		$a_01_1 = {8a 06 90 32 c2 } //2
		$a_01_2 = {6a 40 68 00 30 00 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}