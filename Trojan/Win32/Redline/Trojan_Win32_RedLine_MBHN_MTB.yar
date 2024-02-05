
rule Trojan_Win32_RedLine_MBHN_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 41 64 65 64 67 72 33 00 00 00 00 76 6a 78 68 55 69 73 61 31 } //00 00 
	condition:
		any of ($a_*)
 
}