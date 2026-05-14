
rule Trojan_Win32_Tiny_A_AMTB{
	meta:
		description = "Trojan:Win32/Tiny.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 31 38 35 2e 32 31 35 2e 31 31 33 2e 36 36 2f } //http://185.215.113.66/  4
	condition:
		((#a_80_0  & 1)*4) >=4
 
}