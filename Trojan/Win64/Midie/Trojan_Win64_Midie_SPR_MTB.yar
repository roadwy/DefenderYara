
rule Trojan_Win64_Midie_SPR_MTB{
	meta:
		description = "Trojan:Win64/Midie.SPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 ff 45 33 c9 48 89 7c 24 30 45 33 c0 c7 44 24 28 ?? ?? ?? ?? ba ?? ?? ?? ?? c7 44 24 20 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b e8 48 83 f8 ff 75 } //3
		$a_03_1 = {c7 44 24 28 ?? ?? ?? ?? 48 83 64 24 20 00 48 8d 15 ?? ?? ?? ?? 33 c9 45 33 c9 ff 15 ?? ?? ?? ?? 48 83 f8 20 0f 9f c0 48 83 c4 38 } //3
		$a_01_2 = {70 00 6f 00 73 00 64 00 66 00 63 00 63 00 2e 00 65 00 78 00 65 00 } //1 posdfcc.exe
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1) >=7
 
}