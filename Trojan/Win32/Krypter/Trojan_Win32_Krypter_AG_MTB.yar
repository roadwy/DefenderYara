
rule Trojan_Win32_Krypter_AG_MTB{
	meta:
		description = "Trojan:Win32/Krypter.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 c7 45 ?? ?? ?? ?? ?? 8b 45 ?? 8b 4d ?? d3 e8 8b 4d ?? 89 01 8b 55 ?? 8b 02 03 45 ?? 8b 4d ?? 89 01 8b e5 5d c2 } //10
		$a_01_1 = {56 69 73 75 61 6c 20 43 2b 2b } //10 Visual C++
		$a_03_2 = {55 8b ec 51 c7 45 ?? ?? ?? ?? ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 08 03 4d ?? 8b 55 ?? 89 0a 8b e5 5d c2 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10) >=30
 
}