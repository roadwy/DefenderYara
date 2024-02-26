
rule Trojan_Win32_Zenpack_MBKF_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MBKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 71 68 65 6e 72 6e 65 77 64 36 38 2e 64 6c 6c 00 45 61 6c 45 73 6e 65 61 74 61 79 73 78 78 74 } //01 00  煮敨牮敮摷㠶搮汬䔀污獅敮瑡祡硳瑸
		$a_01_1 = {7a 3a 5c 76 45 41 69 5c 6a 31 4b 73 57 70 2e 70 64 62 } //00 00  z:\vEAi\j1KsWp.pdb
	condition:
		any of ($a_*)
 
}