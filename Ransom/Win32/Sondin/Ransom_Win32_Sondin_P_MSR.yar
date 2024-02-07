
rule Ransom_Win32_Sondin_P_MSR{
	meta:
		description = "Ransom:Win32/Sondin.P!MSR,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 6e 61 6d 65 22 3a 22 7b 45 58 54 7d 2d 72 65 61 64 6d 65 2e 74 78 74 22 } //01 00  nname":"{EXT}-readme.txt"
		$a_01_1 = {64 62 67 22 3a 66 61 6c 73 65 } //01 00  dbg":false
		$a_01_2 = {66 61 73 74 22 3a 66 61 6c 73 65 } //01 00  fast":false
		$a_01_3 = {77 69 70 65 22 3a 66 61 6c 73 65 } //01 00  wipe":false
		$a_01_4 = {77 68 74 22 3a 7b 22 66 6c 64 22 3a 5b } //01 00  wht":{"fld":[
		$a_01_5 = {6a 61 78 2d 69 6e 74 65 72 69 6d 2d 61 6e 64 2d 70 72 6f 6a 65 63 74 6d 61 6e 61 67 65 6d 65 6e 74 2e 63 6f 6d } //00 00  jax-interim-and-projectmanagement.com
		$a_01_6 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}