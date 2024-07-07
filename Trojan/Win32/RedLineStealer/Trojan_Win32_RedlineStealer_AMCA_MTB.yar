
rule Trojan_Win32_RedlineStealer_AMCA_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.AMCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d0 88 45 db 0f b6 4d db c1 f9 07 0f b6 55 db d1 e2 0b ca 88 4d db 0f b6 45 db 2b 45 dc 88 45 db } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}