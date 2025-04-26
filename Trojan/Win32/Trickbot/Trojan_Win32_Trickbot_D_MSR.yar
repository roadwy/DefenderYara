
rule Trojan_Win32_Trickbot_D_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.D!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 23 4a 6e 4b 55 33 58 7b } //1 l#JnKU3X{
		$a_01_1 = {7e 25 41 45 23 70 73 52 42 4b 58 6e 68 51 65 6f 6c 24 6c 54 2a 77 24 55 69 35 47 61 6d 3f 58 51 6e 37 24 6a 65 73 50 31 40 61 58 54 } //1 ~%AE#psRBKXnhQeol$lT*w$Ui5Gam?XQn7$jesP1@aXT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}