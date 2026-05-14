
rule Trojan_Win32_PureCrypter_SWPC_MTB{
	meta:
		description = "Trojan:Win32/PureCrypter.SWPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 20 20 20 20 20 9c fd 00 00 00 a0 9b 00 00 22 00 00 00 72 9b 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 69 64 61 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}