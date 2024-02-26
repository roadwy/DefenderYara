
rule Trojan_Win32_DarkComet_ADR_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 56 50 ff d3 85 c0 75 12 8d 4c 24 10 51 ff d5 8d 54 24 10 52 ff 15 20 f1 40 00 6a 00 6a 00 6a 00 8d 44 24 1c 50 } //00 00 
	condition:
		any of ($a_*)
 
}