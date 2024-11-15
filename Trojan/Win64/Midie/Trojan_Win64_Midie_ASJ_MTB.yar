
rule Trojan_Win64_Midie_ASJ_MTB{
	meta:
		description = "Trojan:Win64/Midie.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b d0 4c 8d 05 ?? ?? ff ff 49 8b cf 48 8b f8 ff 15 ?? ?? ?? ?? 4c 89 6c 24 30 4c 8b cf 44 89 6c 24 28 45 33 c0 33 d2 48 89 5c 24 20 49 8b cf ff 15 ?? ?? ?? ?? 41 b9 18 00 00 00 4c 89 6c 24 20 4c 8d 44 24 50 48 8b d3 49 8b cf ff 15 ?? ?? ?? ?? b9 64 00 00 00 ff 15 } //4
		$a_01_1 = {49 8d 04 30 49 2b d0 0f 1f 40 00 0f 1f 84 00 00 00 00 00 44 30 38 48 8d 40 01 48 83 ea 01 75 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}