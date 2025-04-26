
rule Trojan_Win32_Manuscrypt_NEAA_MTB{
	meta:
		description = "Trojan:Win32/Manuscrypt.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 8d 4d e4 e8 77 08 00 00 8b d0 c6 45 fc 01 83 ec 10 0f 10 45 98 8b 75 f0 8b cc 8b 3e 0f 11 01 8b cb } //10
		$a_01_1 = {76 00 6e 00 63 00 76 00 69 00 65 00 77 00 65 00 72 00 } //5 vncviewer
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}