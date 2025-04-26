
rule Trojan_Win32_Redline_AMAC_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 45 db 0f b6 4d db 81 c1 ?? ?? ?? ?? 88 4d db 0f b6 55 db c1 fa 07 0f b6 45 db d1 e0 0b d0 88 55 db 0f b6 4d db f7 d9 88 4d db 0f b6 55 db 2b 55 dc 88 55 db 0f b6 45 db f7 d8 88 45 db 0f b6 4d db f7 d1 88 4d db 8b 55 dc 8a 45 db 88 44 15 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}