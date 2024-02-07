
rule Ransom_Win32_DarkSide_DA_MTB{
	meta:
		description = "Ransom:Win32/DarkSide.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 73 20 61 6e 64 20 73 65 72 76 65 72 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your computers and servers are encrypted
		$a_81_1 = {57 65 6c 63 6f 6d 65 20 74 6f 20 44 61 72 6b 53 69 64 65 } //01 00  Welcome to DarkSide
		$a_81_2 = {74 6f 72 70 72 6f 6a 65 63 74 2e 6f 72 67 } //01 00  torproject.org
		$a_81_3 = {44 4f 20 4e 4f 54 20 4d 4f 44 49 46 59 20 6f 72 20 74 72 79 20 74 6f 20 52 45 43 4f 56 45 52 20 61 6e 79 20 66 69 6c 65 73 20 79 6f 75 72 73 65 6c 66 } //00 00  DO NOT MODIFY or try to RECOVER any files yourself
	condition:
		any of ($a_*)
 
}