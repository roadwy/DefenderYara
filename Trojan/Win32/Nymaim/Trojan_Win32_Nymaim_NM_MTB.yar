
rule Trojan_Win32_Nymaim_NM_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 10 89 44 24 90 01 01 8b 4c 24 18 89 e2 89 4a 90 01 01 89 02 e8 39 00 00 00 83 ec 90 01 01 8b 44 24 1c 05 90 01 04 89 44 24 40 8b 44 24 90 01 01 8b 4c 24 1c 89 48 90 01 01 8b 44 24 44 8b 4c 24 90 01 01 89 48 58 8b 44 24 1c 90 00 } //5
		$a_01_1 = {73 77 61 6e 6b 5f 74 6f 6f 6c 32 2e 70 64 62 } //1 swank_tool2.pdb
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}