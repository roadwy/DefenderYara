
rule Trojan_Win32_Crypter_DC_MTB{
	meta:
		description = "Trojan:Win32/Crypter.DC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {19 03 00 e9 30 00 04 00 00 de 39 00 00 e9 00 4b 06 00 e9 9e 00 02 00 00 28 eb 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}