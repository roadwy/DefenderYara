
rule Trojan_Win32_StealC_MBFV_MTB{
	meta:
		description = "Trojan:Win32/StealC.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 31 a2 00 00 01 44 24 90 01 01 8b 54 24 90 01 01 8a 04 0a 8b 15 90 01 04 88 04 0a 41 3b 0d 90 01 04 72 d5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}