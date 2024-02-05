
rule Trojan_Win32_IcedId_SIBE_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 37 81 fd 90 01 04 90 18 90 02 55 8b 35 90 01 04 90 02 05 8d bc 2e 90 01 04 8b 37 90 02 0a 81 c6 90 01 04 90 02 05 83 c5 04 90 02 10 89 37 90 00 } //01 00 
		$a_02_1 = {8b 45 08 89 45 90 01 01 90 02 f0 8b 75 90 1b 00 90 02 0a ff e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}