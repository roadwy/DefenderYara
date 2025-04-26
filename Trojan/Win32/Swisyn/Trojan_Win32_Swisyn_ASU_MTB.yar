
rule Trojan_Win32_Swisyn_ASU_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.ASU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 18 4c 00 00 00 89 74 24 1c 89 44 24 20 c7 44 24 24 20 ?? bf 00 89 5c 24 28 89 5c 24 2c c7 44 24 30 01 00 00 00 89 4c 24 34 c7 44 24 38 00 01 00 00 89 5c 24 3c 89 5c 24 40 89 5c 24 44 c7 44 24 48 e0 ?? bf 00 66 89 5c 24 50 66 89 5c 24 52 c7 44 24 54 d4 ?? bf 00 89 5c 24 5c c7 44 24 4c 06 00 20 00 ff 15 } //2
		$a_03_1 = {ff d7 8b 1d ac ?? bf 00 50 ff d3 68 bc ?? bf 00 68 a0 ?? bf 00 8b f0 ff d7 50 ff d3 3b f5 8b f8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}