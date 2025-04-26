
rule Backdoor_WinNT_Rustock_gen_D{
	meta:
		description = "Backdoor:WinNT/Rustock.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {75 7b 80 7f 09 32 0f 85 ?? ?? ?? ?? 80 7f 0a 30 0f 85 ?? ?? ?? ?? 80 7f 0b 30 } //1
		$a_01_1 = {8b f3 03 34 8f 33 c0 c1 c0 07 32 06 46 80 3e 00 75 f5 35 ad 6d bf e8 74 0a 41 3b 4a 18 75 e1 } //1
		$a_03_2 = {3d de c0 ad de 75 0d 83 65 ?? 00 eb 07 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}