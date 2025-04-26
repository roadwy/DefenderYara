
rule Trojan_Win32_CryptBot_XZ_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 b0 07 00 00 10 00 00 00 3c 04 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 6c 16 00 00 00 c0 07 00 00 08 00 00 00 4c 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}