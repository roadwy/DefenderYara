
rule Trojan_Win32_Tibs_GA{
	meta:
		description = "Trojan:Win32/Tibs.GA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {87 02 03 55 08 03 55 0c (|90 09 20 00) [0-50] 0f c8 b9 ?? ?? ?? ?? eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}