
rule Trojan_Win32_RedLine_RDBD_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b c2 83 e0 03 8a 80 90 01 04 30 04 32 42 3b d7 72 ed 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}