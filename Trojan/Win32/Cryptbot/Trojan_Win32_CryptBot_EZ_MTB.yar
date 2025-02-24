
rule Trojan_Win32_CryptBot_EZ_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 d4 05 00 00 00 90 06 00 00 04 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_CryptBot_EZ_MTB_2{
	meta:
		description = "Trojan:Win32/CryptBot.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 e0 70 00 00 10 00 00 00 78 27 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 f0 70 00 00 00 00 00 00 88 27 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}