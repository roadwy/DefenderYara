
rule Trojan_Win32_Redlinestealer_AMBE_MTB{
	meta:
		description = "Trojan:Win32/Redlinestealer.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 db 0f b6 4d db f7 d9 88 4d db 0f b6 55 db c1 fa 07 0f b6 45 db d1 e0 0b d0 88 55 db } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}