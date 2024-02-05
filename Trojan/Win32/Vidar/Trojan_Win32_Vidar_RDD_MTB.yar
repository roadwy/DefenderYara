
rule Trojan_Win32_Vidar_RDD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b f8 33 f6 c6 04 1f 00 85 db 74 36 8b 45 08 2b c7 89 45 08 8b 45 0c 8d 48 01 8a 10 40 84 d2 } //00 00 
	condition:
		any of ($a_*)
 
}