
rule Trojan_Win32_Redline_PCD_MTB{
	meta:
		description = "Trojan:Win32/Redline.PCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 90 01 08 89 45 0c 8b 45 e8 01 45 0c ff 75 fc 8d 45 f0 50 e8 ee fe ff ff 8b 45 f0 33 45 0c 2b f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}