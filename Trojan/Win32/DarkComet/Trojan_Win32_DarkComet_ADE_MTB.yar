
rule Trojan_Win32_DarkComet_ADE_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.ADE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 6a 00 53 68 2c 88 48 00 6a 00 6a 00 e8 ?? ?? ?? ?? db 6d e8 d8 25 ac 8a 48 00 db 7d e8 9b db 6d e8 d8 1d a4 8a 48 00 9b df e0 9e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}