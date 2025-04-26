
rule Trojan_Win32_Upatre_A_MTB{
	meta:
		description = "Trojan:Win32/Upatre.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 10 8d 54 24 34 51 52 ff 15 ?? 21 40 00 8b 35 ec 21 40 00 8d 44 24 3c 68 10 35 40 00 50 ff ?? 8b 8c 24 4c 01 00 00 8b d8 6a 00 51 53 ff 15 ?? 21 40 00 8b 94 24 60 01 00 00 68 0c 35 40 00 52 ff ?? 57 8b e8 ff 15 ?? 21 40 00 8b f0 83 c4 28 85 f6 } //2
		$a_03_1 = {53 6a 01 57 56 ff 15 ?? 21 40 00 55 6a 01 57 56 ff 15 ?? 21 40 00 55 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}