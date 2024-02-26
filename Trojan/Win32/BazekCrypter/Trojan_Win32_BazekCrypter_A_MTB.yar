
rule Trojan_Win32_BazekCrypter_A_MTB{
	meta:
		description = "Trojan:Win32/BazekCrypter.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {46 8b 44 87 90 01 01 33 c2 89 01 83 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}