
rule Trojan_Win32_Tibs_GK{
	meta:
		description = "Trojan:Win32/Tibs.GK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 ad 69 c0 00 90 01 02 00 90 02 06 66 ad c1 90 03 01 01 c0 c8 90 01 01 90 02 04 c1 90 03 01 01 c0 c8 90 01 01 93 81 c3 90 09 1b 00 90 02 0c 90 03 01 04 c3 c2 90 01 02 66 ad 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}