
rule Trojan_Win32_Vidar_SPDH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SPDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 00 6e 00 c7 05 90 01 04 65 00 6c 00 c7 05 90 01 04 33 00 32 00 c7 05 90 01 04 2e 00 64 00 c7 05 90 01 04 6c 00 6c 00 66 89 15 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}