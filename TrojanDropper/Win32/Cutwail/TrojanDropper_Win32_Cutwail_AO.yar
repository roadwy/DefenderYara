
rule TrojanDropper_Win32_Cutwail_AO{
	meta:
		description = "TrojanDropper:Win32/Cutwail.AO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 82 ?? ?? ?? ?? 38 08 74 01 40 56 ff d0 [0-0a] 81 ea ?? ?? ff bf } //1
		$a_01_1 = {01 55 f8 31 03 83 e9 04 7e 14 03 45 f8 } //1
		$a_01_2 = {43 61 6e 63 65 6c 49 6f 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}