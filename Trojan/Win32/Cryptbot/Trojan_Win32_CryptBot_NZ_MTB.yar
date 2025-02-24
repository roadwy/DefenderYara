
rule Trojan_Win32_CryptBot_NZ_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 20 05 00 00 10 00 00 00 64 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 30 05 00 00 02 00 00 00 74 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}