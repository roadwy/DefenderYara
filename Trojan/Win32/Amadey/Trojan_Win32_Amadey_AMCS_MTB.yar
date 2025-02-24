
rule Trojan_Win32_Amadey_AMCS_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AMCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 73 72 63 00 00 00 88 03 00 00 00 90 06 00 00 04 00 00 00 90 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 94 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}