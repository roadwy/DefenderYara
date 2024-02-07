
rule Trojan_Win32_Tocimob_gen_A{
	meta:
		description = "Trojan:Win32/Tocimob.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 3d 15 24 40 00 42 54 43 4d 0f 84 0a 01 00 00 81 3d 15 24 40 00 4c 54 43 4d 0f 84 23 02 00 00 81 3d 15 24 40 00 42 4f 54 48 } //01 00 
		$a_01_1 = {75 2f 75 73 66 74 5f 65 78 74 2e 74 78 74 } //01 00  u/usft_ext.txt
		$a_01_2 = {75 2f 6d 69 6e 65 72 2e 74 78 74 } //01 00  u/miner.txt
		$a_03_3 = {70 74 68 72 65 61 64 47 43 32 2e 74 78 74 00 68 74 74 70 3a 2f 2f 90 02 14 2e 74 78 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}