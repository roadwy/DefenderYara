
rule Trojan_Win32_Redlinestealer_AMCD_MTB{
	meta:
		description = "Trojan:Win32/Redlinestealer.AMCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 f8 06 0f b6 4d db c1 e1 02 0b c1 88 45 db 0f b6 55 db f7 da 88 55 db 0f b6 45 db } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}