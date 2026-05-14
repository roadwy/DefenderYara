
rule Trojan_Win64_Shelma_PGSH_MTB{
	meta:
		description = "Trojan:Win64/Shelma.PGSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_80_0 = {38 35 66 63 64 38 66 33 39 66 65 31 66 64 38 35 38 35 38 35 38 35 63 36 63 62 66 30 66 30 66 30 66 30 66 63 66 66 65 33 65 30 65 66 66 33 65 32 65 32 66 64 66 39 65 32 65 63 65 65 65 66 66 38 64 38 39 33 66 62 64 65 65 32 66 38 63 64 65 32 66 65 66 66 65 62 66 38 64 38 39 33 66 38 64 65 65 32 66 30 38 31 39 64 65 32 64 61 63 31 66 38 64 38 39 64 66 62 65 30 65 64 65 64 66 } //85fcd8f39fe1fd85858585c6cbf0f0f0f0fcffe3e0eff3e2e2fdf9e2eceeeff8d893fbdee2f8cde2feffebf8d893f8dee2f0819de2dac1f8d89dfbe0ededf  5
		$a_80_1 = {6e 6f 74 65 70 61 64 2e 65 78 65 } //notepad.exe  5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5) >=10
 
}
rule Trojan_Win64_Shelma_PGSH_MTB_2{
	meta:
		description = "Trojan:Win64/Shelma.PGSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {f3 41 0f 6f 04 07 48 8d 49 ?? 83 c2 ?? 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 0c 07 f3 0f 6f 41 ?? 66 0f 6f ca 0f 57 c2 f3 41 0f 7f 44 07 ?? f3 41 0f 6f 44 07 ?? 0f 57 c8 f3 41 0f 7f 4c 07 ?? f3 41 0f 6f 44 07 ?? 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 4c 07 ?? 48 83 c0 ?? 48 3d ?? ?? ?? ?? 7c } //5
		$a_03_1 = {f3 0f 6f 40 ?? 48 8d 40 ?? 66 0f 6f ca 0f 57 c8 f3 0f 7f 48 ?? 66 0f 6f ca f3 0f 6f 40 ?? 0f 57 c2 f3 0f 7f 40 ?? f3 0f 6f 40 ?? 0f 57 c8 f3 0f 7f 48 ?? 66 0f 6f ca f3 0f 6f 40 ?? 0f 57 c8 f3 0f 7f 48 ?? 48 83 ea 01 75 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}