
rule Trojan_Win32_CryptBot_ZA_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 72 73 72 63 00 00 00 9c 05 00 00 00 60 00 00 00 06 00 00 00 32 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 20 00 00 00 80 00 00 00 02 00 00 00 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}