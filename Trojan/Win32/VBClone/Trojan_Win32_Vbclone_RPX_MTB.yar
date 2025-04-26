
rule Trojan_Win32_Vbclone_RPX_MTB{
	meta:
		description = "Trojan:Win32/Vbclone.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 f8 64 35 00 00 00 00 00 ff cc 31 00 04 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}