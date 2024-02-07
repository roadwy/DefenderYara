
rule Ransom_Win32_Basta_PB_MTB{
	meta:
		description = "Ransom:Win32/Basta.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c8 8b 1e 83 e1 90 01 01 8b 7e 90 01 01 33 d8 8b 76 08 33 f8 33 f0 d3 cf d3 ce d3 cb 3b fe 90 00 } //01 00 
		$a_01_1 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 62 72 65 61 63 68 65 64 20 61 6e 64 20 61 6c 6c 20 64 61 74 61 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your network has been breached and all data was encrypted
		$a_01_2 = {61 63 63 65 73 73 20 2e 6f 6e 69 6f 6e 20 77 65 62 73 69 74 65 } //01 00  access .onion website
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 4d 41 58 20 6e 6f 74 65 70 61 64 2e 65 78 65 } //00 00  cmd.exe /c start /MAX notepad.exe
	condition:
		any of ($a_*)
 
}