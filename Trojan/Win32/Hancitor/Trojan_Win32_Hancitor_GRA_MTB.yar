
rule Trojan_Win32_Hancitor_GRA_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 89 e5 8b 45 90 02 02 8b 4d 90 02 02 8b 55 90 02 02 31 db 89 ce 83 e6 03 75 90 02 02 8b 5d 90 02 01 66 01 da 66 f7 da 6b d2 03 c1 ca 08 89 55 90 02 01 30 10 40 e2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}