
rule Ransom_MSIL_LockScreen_D{
	meta:
		description = "Ransom:MSIL/LockScreen.D,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 3a 5c 30 78 30 30 5c 5b 72 61 6e 73 6f 6d 77 61 72 65 5d 5c } //01 00  L:\0x00\[ransomware]\
		$a_01_1 = {54 69 6d 65 72 31 5f 54 69 63 6b } //01 00  Timer1_Tick
		$a_01_2 = {73 00 64 00 63 00 6c 00 74 00 } //01 00  sdclt
		$a_01_3 = {72 00 73 00 74 00 72 00 75 00 69 00 } //01 00  rstrui
		$a_01_4 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //00 00  powershell
		$a_00_5 = {5d 04 00 00 2a } //34 03 
	condition:
		any of ($a_*)
 
}