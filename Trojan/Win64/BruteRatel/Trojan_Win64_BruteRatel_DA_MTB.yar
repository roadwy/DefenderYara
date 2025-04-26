
rule Trojan_Win64_BruteRatel_DA_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b cb 48 83 f8 1c 48 0f 45 c8 42 0f b6 04 09 30 02 48 8d 41 01 41 ff c0 48 8d 52 01 41 81 f8 e0 93 04 00 72 } //1
		$a_01_1 = {6a 69 6b 6f 65 77 61 72 66 6b 6d 7a 73 64 6c 68 66 6e 75 69 77 61 65 6a 72 70 61 77 } //1 jikoewarfkmzsdlhfnuiwaejrpaw
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}