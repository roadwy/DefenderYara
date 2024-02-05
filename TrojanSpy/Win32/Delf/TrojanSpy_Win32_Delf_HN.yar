
rule TrojanSpy_Win32_Delf_HN{
	meta:
		description = "TrojanSpy:Win32/Delf.HN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2d 20 4d 73 6e 28 00 ff ff ff ff 01 00 00 00 29 00 00 00 ff ff ff ff 08 00 00 00 20 2d 20 57 41 42 20 28 00 } //01 00 
		$a_01_1 = {7d 03 47 eb 05 bf 01 00 00 00 8b 45 e4 33 db 8a 5c 38 ff 33 5d e0 3b 5d ec 7f 0b 81 c3 ff 00 00 00 2b 5d ec eb 03 } //00 00 
	condition:
		any of ($a_*)
 
}