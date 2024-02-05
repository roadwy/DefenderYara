
rule Trojan_Win32_Sabsik_PJT_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.PJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 48 f8 8b 38 8b 50 fc 03 4d fc 03 7d 08 8b da 4a 85 db 74 0a 42 8a 1f 88 19 41 47 4a 75 f7 83 c0 28 ff 4d 0c 75 d9 } //00 00 
	condition:
		any of ($a_*)
 
}