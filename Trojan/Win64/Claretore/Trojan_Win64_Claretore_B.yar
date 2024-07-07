
rule Trojan_Win64_Claretore_B{
	meta:
		description = "Trojan:Win64/Claretore.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 28 01 23 45 67 c7 44 24 2c 89 ab cd ef c7 44 24 30 fe dc ba 98 c7 44 24 34 76 54 32 10 } //1
		$a_01_1 = {77 76 3d 25 73 26 75 69 64 3d 25 64 26 6c 6e 67 3d 25 73 26 6d 69 64 3d 25 73 26 72 65 73 3d 25 73 26 76 3d 25 30 38 58 } //1 wv=%s&uid=%d&lng=%s&mid=%s&res=%s&v=%08X
		$a_00_2 = {24 6d 69 64 3d 25 53 26 75 69 64 3d 25 64 26 76 65 72 73 69 6f 6e 3d 25 73 24 } //1 $mid=%S&uid=%d&version=%s$
		$a_01_3 = {43 3a 5c 50 72 6f 6a 65 63 74 5c 55 4d 5c 62 72 61 6e 63 68 65 73 5c 75 73 65 72 6e 61 6d 65 5c 62 69 6e 5c 5b 52 65 6c 65 61 73 65 2e 78 36 34 5d 43 6c 69 63 6b 65 72 2e 70 64 62 } //1 C:\Project\UM\branches\username\bin\[Release.x64]Clicker.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}