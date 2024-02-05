
rule Worm_Win32_Vobfus_AI_MTB{
	meta:
		description = "Worm:Win32/Vobfus.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 67 46 6c 75 73 68 4b 65 79 } //01 00 
		$a_01_1 = {4d 61 73 6b 45 64 42 6f 78 31 } //01 00 
		$a_01_2 = {43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 57 } //01 00 
		$a_01_3 = {48 61 70 70 79 46 65 65 74 2e 64 6c 6c } //01 00 
		$a_01_4 = {77 00 77 00 77 00 2e 00 41 00 72 00 76 00 69 00 6e 00 64 00 65 00 72 00 2e 00 63 00 6f 00 2e 00 75 00 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}