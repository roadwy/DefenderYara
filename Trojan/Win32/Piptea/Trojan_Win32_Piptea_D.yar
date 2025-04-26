
rule Trojan_Win32_Piptea_D{
	meta:
		description = "Trojan:Win32/Piptea.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 48 28 89 4d ?? ff 55 } //1
		$a_03_1 = {8d 45 dc 50 ff 15 ?? ?? ?? ?? 83 7d f0 00 76 18 } //1
		$a_01_2 = {c7 45 c0 b9 79 37 9e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}