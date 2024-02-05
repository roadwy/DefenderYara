
rule Trojan_Win32_Remcos_B_MTB{
	meta:
		description = "Trojan:Win32/Remcos.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {55 8b ec 81 ec 9c 00 00 00 56 57 68 00 08 00 00 68 00 30 00 10 b8 00 a2 07 10 e8 } //03 00 
		$a_80_1 = {64 66 67 68 37 66 64 35 34 68 66 64 35 68 34 } //dfgh7fd54hfd5h4  03 00 
		$a_80_2 = {6b 79 74 68 64 69 67 75 6c 39 66 } //kythdigul9f  03 00 
		$a_80_3 = {6b 79 74 68 64 69 67 75 6c 66 32 } //kythdigulf2  03 00 
		$a_80_4 = {6b 79 74 68 64 69 67 75 6c 66 33 } //kythdigulf3  00 00 
	condition:
		any of ($a_*)
 
}