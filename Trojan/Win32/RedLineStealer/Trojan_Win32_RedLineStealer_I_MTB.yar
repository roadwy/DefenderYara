
rule Trojan_Win32_RedLineStealer_I_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 04 90 01 04 30 81 90 01 04 41 89 4c 24 90 01 01 81 f9 90 01 04 72 90 01 01 90 09 05 00 03 c2 0f b6 c0 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}