
rule Trojan_BAT_ShellCodeRunner_NS_MTB{
	meta:
		description = "Trojan:BAT/ShellCodeRunner.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 16 fe 0e ?? ?? ?? ?? 2b 25 00 09 fe 0c ?? ?? ?? 00 07 fe 0c ?? ?? ?? ?? 93 28 15 00 00 0a 9c 00 fe 0c ?? ?? ?? ?? 17 58 fe 0e } //3
		$a_01_1 = {43 61 6c 69 73 74 69 72 6d 61 46 6f 6e 6b 73 69 79 6f 6e 75 } //2 CalistirmaFonksiyonu
		$a_01_2 = {53 70 6f 74 69 66 79 73 2e 65 78 65 } //1 Spotifys.exe
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}