
rule Trojan_Win32_CryptBot_DZ_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 50 65 00 00 10 00 00 00 6c 27 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 60 65 00 00 00 00 00 00 7c 27 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}