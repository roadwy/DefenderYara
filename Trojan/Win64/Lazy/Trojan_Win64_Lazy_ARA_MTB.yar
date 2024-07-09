
rule Trojan_Win64_Lazy_ARA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 c3 80 e3 ?? 80 cb ?? 24 ?? 30 d8 34 ?? 88 05 } //2
		$a_03_1 = {89 c2 80 e2 ?? 80 ca ?? 24 ?? 30 d0 34 ?? 88 05 } //2
		$a_01_2 = {74 65 73 74 31 32 33 31 32 33 31 32 33 31 32 33 } //3 test123123123123
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*3) >=5
 
}
rule Trojan_Win64_Lazy_ARA_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 50 50 4c 4b 69 6c 6c 65 72 2e 70 64 62 } //2 \PPLKiller.pdb
		$a_80_1 = {5c 54 65 6d 70 5c 52 54 43 6f 72 65 36 34 2e 73 79 73 } //\Temp\RTCore64.sys  2
		$a_80_2 = {64 69 73 61 62 6c 65 50 50 4c } //disablePPL  2
		$a_80_3 = {64 69 73 61 62 6c 65 4c 53 41 50 72 6f 74 65 63 74 69 6f 6e } //disableLSAProtection  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=6
 
}