
rule Trojan_Win32_RedLine_RDBI_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b d0 83 e2 03 8a 8a 90 01 04 30 0c 38 40 3b c6 72 ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}