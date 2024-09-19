
rule Trojan_Win32_DarkComet_AKM_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.AKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 6a 00 53 68 d8 36 15 00 6a 00 6a 00 e8 8b 40 f8 ff db 6d e8 d8 25 b0 39 15 00 db 7d e8 9b db 6d e8 d8 1d a8 39 15 00 9b df e0 9e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}