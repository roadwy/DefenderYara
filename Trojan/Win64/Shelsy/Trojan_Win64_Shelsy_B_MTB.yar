
rule Trojan_Win64_Shelsy_B_MTB{
	meta:
		description = "Trojan:Win64/Shelsy.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 6f 77 6e 6c 6f 61 64 73 5c 50 72 6f 78 69 6e 65 4e 65 77 41 75 74 68 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 78 69 6e 65 2e 70 64 62 } //1 C:\Users\Administrator\Downloads\ProxineNewAuth\x64\Release\Proxine.pdb
		$a_03_1 = {66 89 85 d4 02 00 00 c6 85 d0 02 00 00 4b 80 b5 d1 02 00 00 90 01 01 80 b5 d2 02 00 00 90 01 01 80 b5 d3 02 00 00 90 01 01 34 90 01 01 88 85 d4 02 00 00 80 b5 d5 02 00 00 90 01 01 48 8d 95 d0 02 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}