
rule Trojan_Win32_RedLine_RDEN_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 10 8b 45 0c 8b 45 08 8b 7d 08 8b 75 0c 8b 4d 10 f3 a4 89 45 f4 8b 45 08 } //00 00 
	condition:
		any of ($a_*)
 
}