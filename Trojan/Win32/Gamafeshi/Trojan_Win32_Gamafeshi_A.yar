
rule Trojan_Win32_Gamafeshi_A{
	meta:
		description = "Trojan:Win32/Gamafeshi.A,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {44 47 4d 4e 4f 45 50 00 } //0a 00 
		$a_00_1 = {25 00 73 00 20 00 2d 00 20 00 25 00 73 00 20 00 2d 00 20 00 25 00 32 00 2e 00 32 00 78 00 } //0a 00 
		$a_00_2 = {57 00 49 00 4e 00 57 00 4f 00 52 00 44 00 2e 00 45 00 58 00 45 00 00 00 } //0a 00 
		$a_01_3 = {04 cd ab 34 12 75 } //00 00 
		$a_00_4 = {5d 04 00 00 a8 aa 03 80 5c 21 00 00 aa aa 03 80 00 00 01 00 27 00 0b 00 c8 21 55 72 73 6e } //69 66 
	condition:
		any of ($a_*)
 
}