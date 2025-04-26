
rule Trojan_Win32_Copak_SPDL_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 0e 68 90 04 dc f9 8b 1c 24 83 c4 04 81 c6 04 00 00 00 39 fe 75 e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}