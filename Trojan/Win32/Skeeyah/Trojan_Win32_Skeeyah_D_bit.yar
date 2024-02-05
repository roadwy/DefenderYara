
rule Trojan_Win32_Skeeyah_D_bit{
	meta:
		description = "Trojan:Win32/Skeeyah.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d 0c 8a 0c 0f 8b 45 08 30 0c 18 8d 47 01 99 f7 7d fc 8b fa ff d6 43 3b 5d 10 } //00 00 
	condition:
		any of ($a_*)
 
}