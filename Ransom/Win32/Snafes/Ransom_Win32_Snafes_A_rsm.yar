
rule Ransom_Win32_Snafes_A_rsm{
	meta:
		description = "Ransom:Win32/Snafes.A!rsm,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {51 52 41 50 41 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? 48 2d ?? ?? ?? ?? 50 48 8d 05 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 50 48 8d 05 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? ff d0 41 59 41 58 5a 59 } //10
		$a_03_1 = {0f ae f0 48 8b 54 24 18 48 83 3a 02 [0-06] 48 c7 c0 00 00 00 00 48 c7 c1 01 00 00 00 f0 48 0f b1 0a } //5
		$a_00_2 = {48 89 4c 24 08 48 83 ec 68 c7 44 24 24 00 00 00 00 c7 44 24 2c 00 00 00 00 c7 44 24 20 00 00 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 30 00 00 00 00 48 83 7c 24 70 00 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_00_2  & 1)*5) >=10
 
}