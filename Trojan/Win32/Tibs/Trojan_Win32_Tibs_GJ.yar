
rule Trojan_Win32_Tibs_GJ{
	meta:
		description = "Trojan:Win32/Tibs.GJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f2 52 66 ad 6b c0 90 01 01 90 02 06 66 ad c1 90 03 01 01 c0 c8 90 01 01 90 02 02 c1 90 03 01 01 c0 c8 90 01 01 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}