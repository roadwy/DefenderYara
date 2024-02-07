
rule Trojan_Win32_Emotet_RC{
	meta:
		description = "Trojan:Win32/Emotet.RC,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {3a 4c 6b 6a 33 76 2c 32 75 33 3d 35 33 34 76 33 34 35 62 32 33 34 35 2e 50 44 42 } //05 00  :Lkj3v,2u3=534v345b2345.PDB
		$a_01_1 = {57 74 61 6b 59 30 56 4e 66 6f 2e 70 64 62 } //05 00  WtakY0VNfo.pdb
		$a_01_2 = {42 6f 52 72 54 55 4a 6d 74 56 54 2e 70 64 62 } //05 00  BoRrTUJmtVT.pdb
		$a_01_3 = {49 4b 6c 6c 6c 51 57 67 62 68 65 6a 6b 57 45 4a 4b 48 77 37 5c 5c 77 65 72 72 6e 4a 45 4b 4c 4a 33 32 68 6a 65 6c 6b 6b 2e 50 44 42 } //00 00  IKlllQWgbhejkWEJKHw7\\werrnJEKLJ32hjelkk.PDB
	condition:
		any of ($a_*)
 
}