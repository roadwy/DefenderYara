
rule Trojan_Win32_RedlineStealer_AMBZ_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.AMBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d0 88 45 db 0f b6 4d db c1 f9 06 0f b6 55 db c1 e2 02 0b ca 88 4d db } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}