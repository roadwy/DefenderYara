
rule Trojan_Win32_RedLine_D_MTB{
	meta:
		description = "Trojan:Win32/RedLine.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 05 03 4c 24 20 c7 05 90 01 04 19 36 6b ff 33 cf 31 4c 24 10 c7 05 90 01 04 ff ff ff ff 8b 44 24 10 29 44 24 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}