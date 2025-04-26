
rule Trojan_Win32_Trickbot_A{
	meta:
		description = "Trojan:Win32/Trickbot.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 00 68 00 6f 00 73 00 74 00 } //1 Ghost
		$a_01_1 = {45 00 79 00 65 00 20 00 44 00 65 00 6d 00 6f 00 6e 00 } //1 Eye Demon
		$a_01_2 = {52 00 65 00 64 00 20 00 4b 00 69 00 6c 00 6c 00 61 00 } //1 Red Killa
		$a_01_3 = {53 00 63 00 6f 00 72 00 70 00 69 00 6f 00 6e 00 } //1 Scorpion
		$a_01_4 = {4c 00 65 00 67 00 65 00 6e 00 64 00 2e 00 65 00 78 00 65 00 } //1 Legend.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}