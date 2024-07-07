
rule Trojan_Win32_RedLine_MBEU_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db f7 d8 88 45 db 0f b6 4d db 83 c1 3b 88 4d db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db c1 f8 05 0f b6 4d db c1 e1 03 0b c1 88 45 db 0f b6 55 db 83 c2 7f 88 55 db 8b 45 dc 8a 4d db 88 4c 05 e8 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}