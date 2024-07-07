
rule Trojan_Win32_Dotbot_A{
	meta:
		description = "Trojan:Win32/Dotbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6f 6e 6b 65 79 3a 28 4b 6f 6e 67 29 3a 42 6f 74 6e 65 74 } //1 Donkey:(Kong):Botnet
		$a_01_1 = {53 74 6f 70 44 6c 66 6c 6f 6f 64 } //1 StopDlflood
		$a_01_2 = {68 54 66 6b 34 } //1 hTfk4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}