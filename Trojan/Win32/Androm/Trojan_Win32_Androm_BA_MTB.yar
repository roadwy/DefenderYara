
rule Trojan_Win32_Androm_BA_MTB{
	meta:
		description = "Trojan:Win32/Androm.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 00 00 00 00 80 34 01 90 01 01 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc 05 db 7e 00 00 ff e0 90 00 } //01 00 
		$a_03_1 = {33 c0 55 68 90 01 04 64 ff 30 64 89 20 b9 00 00 00 00 91 f7 f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}