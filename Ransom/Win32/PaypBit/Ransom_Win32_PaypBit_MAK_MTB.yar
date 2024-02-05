
rule Ransom_Win32_PaypBit_MAK_MTB{
	meta:
		description = "Ransom:Win32/PaypBit.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 6c 6c 2c 20 59 6f 75 72 20 53 68 69 74 20 69 73 20 49 6e 73 74 61 6c 6c 65 64 } //01 00 
		$a_01_1 = {50 61 79 70 61 6c 2e 57 69 6e 33 32 2e 52 61 6e 73 6f 6d } //01 00 
		$a_01_2 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}