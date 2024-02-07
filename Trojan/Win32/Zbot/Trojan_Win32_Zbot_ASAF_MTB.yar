
rule Trojan_Win32_Zbot_ASAF_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ASAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c9 81 c1 3a 8e 00 00 81 e1 38 5c 00 00 c1 e1 0c 81 f1 26 51 00 00 c1 e1 04 69 c9 14 79 00 00 81 f9 b9 d3 d4 59 0f 86 } //01 00 
		$a_01_1 = {3f 4b 65 76 64 6e 53 62 65 66 65 64 72 6f 40 40 59 47 48 48 49 40 5a } //01 00  ?KevdnSbefedro@@YGHHI@Z
		$a_01_2 = {68 7c 32 00 00 68 59 4e 00 00 68 6f 87 00 00 68 b4 35 00 00 68 85 67 00 00 68 c2 34 00 00 68 92 57 00 00 68 df 70 00 00 68 ec 67 00 00 ff 15 } //01 00 
		$a_01_3 = {45 76 6b 6e 78 6e 79 6a 74 7a 79 66 2e 64 6c 6c } //00 00  Evknxnyjtzyf.dll
	condition:
		any of ($a_*)
 
}