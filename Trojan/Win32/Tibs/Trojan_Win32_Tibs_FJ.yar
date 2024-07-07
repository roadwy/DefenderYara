
rule Trojan_Win32_Tibs_FJ{
	meta:
		description = "Trojan:Win32/Tibs.FJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {87 ca 83 c4 90 01 01 83 ec 90 01 01 6a 90 01 01 ff 15 90 01 04 90 03 07 07 69 c0 00 90 01 02 00 ba 00 00 01 00 f7 e2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}