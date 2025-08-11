
rule Trojan_Win32_Lazy_SC_MTB{
	meta:
		description = "Trojan:Win32/Lazy.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 90 0c 00 00 10 00 00 00 e0 04 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 73 72 63 00 00 00 14 03 00 00 00 a0 0c 00 00 02 00 00 00 f0 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}