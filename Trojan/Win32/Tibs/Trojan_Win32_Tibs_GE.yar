
rule Trojan_Win32_Tibs_GE{
	meta:
		description = "Trojan:Win32/Tibs.GE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 02 00 00 00 00 0f c1 02 2b 55 08 03 55 0c c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}