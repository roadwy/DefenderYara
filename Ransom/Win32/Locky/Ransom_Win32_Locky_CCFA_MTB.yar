
rule Ransom_Win32_Locky_CCFA_MTB{
	meta:
		description = "Ransom:Win32/Locky.CCFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 85 e4 fe ff ff 03 85 90 01 01 fe ff ff 0f be 08 33 8d 90 01 01 fe ff ff 8b 95 90 01 01 fe ff ff 03 95 90 01 01 fe ff ff 88 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}