
rule Trojan_Win32_CerberCrypt_G_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 c2 88 07 90 42 90 46 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}