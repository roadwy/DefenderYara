
rule Trojan_Win32_Razy_SPDR_MTB{
	meta:
		description = "Trojan:Win32/Razy.SPDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 d8 85 40 00 5a e8 90 01 04 29 cf 31 16 81 c6 01 00 00 00 81 ef ba f0 a8 bc 21 c9 39 de 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}