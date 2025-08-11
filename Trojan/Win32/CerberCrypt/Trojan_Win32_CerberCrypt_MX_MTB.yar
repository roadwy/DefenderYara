
rule Trojan_Win32_CerberCrypt_MX_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 c2 90 88 07 90 42 90 46 90 47 90 49 90 83 f9 } //1
		$a_01_1 = {8a 06 90 32 c2 88 07 42 46 47 49 90 83 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}