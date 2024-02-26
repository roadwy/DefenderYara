
rule Trojan_Win32_Barys_PACS_MTB{
	meta:
		description = "Trojan:Win32/Barys.PACS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 55 08 8b 45 f8 01 d0 0f b6 08 8b 45 f8 83 e0 1f 0f b6 54 05 d8 8b 5d 08 8b 45 f8 01 d8 31 ca 88 10 83 45 f8 01 8b 45 f8 3b 45 0c 72 d2 } //00 00 
	condition:
		any of ($a_*)
 
}