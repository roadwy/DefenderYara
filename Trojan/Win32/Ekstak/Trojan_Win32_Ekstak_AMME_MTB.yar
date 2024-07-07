
rule Trojan_Win32_Ekstak_AMME_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.AMME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 96 0a 00 50 ef 5b 3a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}