
rule Trojan_Win32_Redline_DK_MTB{
	meta:
		description = "Trojan:Win32/Redline.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d db 0f b6 55 db f7 da 88 55 db 0f b6 45 db 2b 45 dc 88 45 db 0f b6 4d db c1 f9 06 0f b6 55 db c1 e2 02 0b ca 88 4d db 0f b6 45 db 2b 45 dc 88 45 db 8b 4d dc 8a 55 db 88 54 0d e8 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}