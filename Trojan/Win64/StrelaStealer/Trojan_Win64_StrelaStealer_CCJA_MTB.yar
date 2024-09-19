
rule Trojan_Win64_StrelaStealer_CCJA_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.CCJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 41 57 41 56 41 55 41 54 56 57 53 48 81 ec ?? ?? ?? ?? 48 8d ac 24 80 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 89 c1 81 e9 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 0f 84 } //1
		$a_03_1 = {03 00 01 00 00 00 01 00 00 00 01 00 00 00 28 ?? 03 00 2c ?? 03 00 30 ?? 03 00 a0 15 00 00 3a ?? 03 00 00 00 6f 75 74 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}