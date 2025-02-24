
rule Trojan_BAT_Heracles_BAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 02 07 6f 92 00 00 0a 03 07 6f 92 00 00 0a 61 60 0a 07 17 58 0b 07 02 6f 1c 00 00 0a 32 e1 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_BAT_Heracles_BAA_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 c1 00 00 70 28 ?? 00 00 0a 72 ed 00 00 70 28 ?? 00 00 0a 26 20 f4 01 00 00 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 2a } //2
		$a_01_1 = {76 00 62 00 70 00 61 00 6e 00 65 00 6c 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 56 00 65 00 72 00 74 00 69 00 67 00 6f 00 42 00 6f 00 6f 00 73 00 74 00 50 00 61 00 6e 00 65 00 6c 00 2e 00 7a 00 69 00 70 00 } //2 vbpanel.com/panel/download/VertigoBoostPanel.zip
		$a_01_2 = {56 00 65 00 72 00 74 00 69 00 67 00 6f 00 42 00 6f 00 6f 00 73 00 74 00 50 00 61 00 6e 00 65 00 6c 00 2e 00 65 00 78 00 65 00 2e 00 63 00 6f 00 6e 00 66 00 69 00 67 00 } //1 VertigoBoostPanel.exe.config
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}