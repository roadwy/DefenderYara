
rule Trojan_Win64_Lazy_ALL_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ALL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f ba f0 0f 49 8d 8f 28 ca 4c 02 48 8d 15 bd 81 03 00 41 89 87 8c 22 db 01 } //3
		$a_03_1 = {45 33 c0 48 89 44 24 28 48 8d 53 04 4c 8d 4d ?? c7 44 24 20 00 01 00 00 48 8d 0d 4a 98 03 00 } //2
		$a_01_2 = {53 41 4b 55 52 41 54 45 43 48 5c 50 72 6f 6a 65 63 74 5c 42 32 39 30 5f 4f 6e 65 44 69 67 69 4d 4d 49 43 5c 4d 53 56 43 5c 6d 72 31 32 65 5c 6d 72 31 32 65 5c 6d 72 31 32 65 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6d 72 31 32 65 2e 70 64 62 } //1 SAKURATECH\Project\B290_OneDigiMMIC\MSVC\mr12e\mr12e\mr12e\x64\Release\mr12e.pdb
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}