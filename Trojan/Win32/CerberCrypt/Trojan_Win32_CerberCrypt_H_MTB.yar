
rule Trojan_Win32_CerberCrypt_H_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 88 07 90 42 46 90 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}