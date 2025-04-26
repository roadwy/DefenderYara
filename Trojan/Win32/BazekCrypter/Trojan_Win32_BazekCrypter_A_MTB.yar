
rule Trojan_Win32_BazekCrypter_A_MTB{
	meta:
		description = "Trojan:Win32/BazekCrypter.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 8b 44 87 ?? 33 c2 89 01 83 c1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}