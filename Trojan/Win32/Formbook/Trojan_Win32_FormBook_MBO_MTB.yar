
rule Trojan_Win32_FormBook_MBO_MTB{
	meta:
		description = "Trojan:Win32/FormBook.MBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11 83 f2 03 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11 83 ea 44 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11 } //01 00 
		$a_03_1 = {89 45 f0 6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15 90 01 04 89 45 f8 6a 00 8d 45 d8 50 8b 4d f0 51 8b 55 f8 52 8b 45 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}