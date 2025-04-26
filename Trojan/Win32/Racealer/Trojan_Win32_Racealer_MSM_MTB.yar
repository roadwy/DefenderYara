
rule Trojan_Win32_Racealer_MSM_MTB{
	meta:
		description = "Trojan:Win32/Racealer.MSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {81 f3 07 eb dd 13 81 6c 24 14 52 ef 6f 62 b8 41 e5 64 03 81 6c 24 14 68 19 2a 14 81 44 24 14 be 08 9a 76 8b 4c 24 14 8b 54 24 10 } //1
		$a_02_1 = {81 e3 8d 5a 7d 6f c1 e0 04 81 6c 24 14 82 66 52 58 c1 eb 12 81 44 24 14 84 66 52 58 8b 54 24 14 0f af d6 8d 4c 95 00 8b 54 24 1c e8 ?? ?? ?? ?? 46 c7 05 ?? ?? ?? ?? ?? 42 ae 83 3b f7 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}