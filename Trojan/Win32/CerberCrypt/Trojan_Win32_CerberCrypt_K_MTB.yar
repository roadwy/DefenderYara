
rule Trojan_Win32_CerberCrypt_K_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 10 00 00 90 } //2
		$a_01_1 = {8a 06 90 32 c2 88 07 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}