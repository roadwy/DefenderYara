
rule Trojan_Win64_Icedid_GB_MTB{
	meta:
		description = "Trojan:Win64/Icedid.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {44 31 f3 88 5c 24 ?? c7 44 24 [0-05] 8a 54 24 ?? 80 ea ?? 80 c2 ?? 80 c2 ?? 88 54 24 ?? c7 44 24 [0-05] 8a 54 24 ?? 48 8b 4c 24 ?? 88 11 c7 44 24 [0-05] 48 8b 4c 24 ?? 48 81 c1 01 00 00 00 48 89 4c 24 ?? c7 44 24 [0-05] 44 8b 5c 24 ?? 83 e8 ff 41 29 c3 44 89 5c 24 ?? 41 83 fb 00 0f 84 [0-04] c7 44 24 [0-05] e9 } //10
		$a_80_1 = {50 6c 75 67 69 6e 49 6e 69 74 } //PluginInit  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}