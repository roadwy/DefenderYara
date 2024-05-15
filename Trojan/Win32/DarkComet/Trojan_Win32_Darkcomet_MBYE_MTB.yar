
rule Trojan_Win32_Darkcomet_MBYE_MTB{
	meta:
		description = "Trojan:Win32/Darkcomet.MBYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 36 40 00 9e f9 b0 01 00 ff ff ff 08 00 00 00 01 00 00 00 0a 00 06 00 e9 00 00 00 60 3b 40 00 e8 52 40 00 78 2c 40 00 78 00 00 00 7a 00 00 00 83 } //00 00 
	condition:
		any of ($a_*)
 
}