
rule Trojan_Win32_Tibs_JE{
	meta:
		description = "Trojan:Win32/Tibs.JE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0d 40 02 fe 7f 69 c9 90 01 04 01 c8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}