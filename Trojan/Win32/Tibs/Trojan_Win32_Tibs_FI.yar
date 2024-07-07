
rule Trojan_Win32_Tibs_FI{
	meta:
		description = "Trojan:Win32/Tibs.FI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {87 ca 83 c4 90 01 01 83 c4 90 01 01 8d 1d 90 01 02 40 00 90 02 02 6a 90 01 01 ff 90 03 01 01 13 d3 69 c0 00 00 01 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}