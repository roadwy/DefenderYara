
rule Trojan_Win32_Redline_DV_MTB{
	meta:
		description = "Trojan:Win32/Redline.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d db 0f b6 55 db c1 fa 03 0f b6 45 db c1 e0 05 0b d0 88 55 db 8b 4d dc 8a 55 db 88 54 0d e8 e9 a8 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}