
rule Trojan_Win32_Vidar_RPT_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b1 6d b0 6c 68 90 01 04 88 0d 90 01 04 c6 05 90 01 04 73 c6 05 90 01 04 33 a2 90 01 04 c6 05 90 01 04 64 88 0d 90 01 04 c6 05 90 01 04 69 c6 05 90 01 04 32 c6 05 90 01 04 2e c6 05 90 01 04 67 a2 90 01 04 c6 05 90 01 04 00 ff 15 90 01 04 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}