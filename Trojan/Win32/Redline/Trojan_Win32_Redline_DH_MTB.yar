
rule Trojan_Win32_Redline_DH_MTB{
	meta:
		description = "Trojan:Win32/Redline.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 db 0f b6 55 db f7 da 88 55 db 0f b6 45 db d1 f8 0f b6 4d db c1 e1 07 0b c1 88 45 db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db 83 c0 69 88 45 db 8b 4d dc 8a 55 db 88 54 0d e8 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}