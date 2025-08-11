
rule Trojan_Win32_Fragtor_AO_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 56 57 56 81 e6 b8 37 00 00 81 ce fe 4b 00 00 81 e6 1d 61 01 00 81 ee 00 21 00 00 5e 50 50 83 c4 04 81 e8 4b 46 00 00 81 f0 4e 0e 01 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}