
rule Trojan_BAT_Nanocore_NCA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {18 72 ad 33 00 70 14 d0 ?? ?? ?? 02 28 ?? ?? ?? 0a 18 8d ?? ?? ?? 01 25 16 17 14 28 ?? ?? ?? 0a a2 25 17 16 14 28 ?? ?? ?? 0a a2 28 ?? ?? ?? 0a } //5
		$a_01_1 = {51 75 61 6e 4c 79 42 61 6e 67 44 69 61 43 44 2e 50 72 6f 70 65 72 74 69 65 73 } //1 QuanLyBangDiaCD.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}