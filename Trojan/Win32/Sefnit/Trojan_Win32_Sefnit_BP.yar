
rule Trojan_Win32_Sefnit_BP{
	meta:
		description = "Trojan:Win32/Sefnit.BP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {13 14 5f 5f c7 85 10 fd ff ff 5f 5f 5c 2d c7 85 14 fd ff ff 50 64 7f 5d c7 85 18 fd ff ff 2f 67 7d 2c c7 85 1c fd ff ff 5b 5f 5f 5f } //00 00 
	condition:
		any of ($a_*)
 
}