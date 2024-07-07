
rule Trojan_Win32_CerberCrypt_F_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 90 88 07 90 42 90 46 47 49 83 f9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}