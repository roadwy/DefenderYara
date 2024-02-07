
rule Trojan_Win32_DelfCrypt_A{
	meta:
		description = "Trojan:Win32/DelfCrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 c6 04 24 54 c6 44 24 01 42 c6 44 24 02 45 5a } //01 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 4d 6f 68 61 6d 6d 65 64 5c 44 65 73 6b 74 6f 70 5c 4c 69 30 6e 20 50 72 6f 6a 65 63 74 73 5c 4c 69 76 65 46 72 65 65 54 65 61 6d 20 43 72 79 70 74 65 72 5c 43 6f 6d 70 69 6c 65 72 5c 55 6e 69 74 31 2e 70 61 73 } //01 00  C:\Users\Mohammed\Desktop\Li0n Projects\LiveFreeTeam Crypter\Compiler\Unit1.pas
		$a_01_2 = {53 63 72 61 74 63 68 70 61 64 20 73 79 6e 63 68 20 70 72 6f 62 6c 65 6d } //00 00  Scratchpad synch problem
	condition:
		any of ($a_*)
 
}