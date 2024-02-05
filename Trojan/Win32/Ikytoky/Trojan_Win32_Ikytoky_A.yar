
rule Trojan_Win32_Ikytoky_A{
	meta:
		description = "Trojan:Win32/Ikytoky.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 20 8d 4d d0 51 68 6b 6b 00 00 68 6b 6b 00 00 e8 } //01 00 
		$a_01_1 = {68 f4 01 00 00 8b 8d 60 fe ff ff 51 8b 95 50 fe ff ff 52 6a 00 0f b7 45 14 50 8d 8d 48 fa ff ff 51 8b 95 64 fe ff ff 52 8b 85 4c fe ff ff 50 e8 } //00 00 
	condition:
		any of ($a_*)
 
}