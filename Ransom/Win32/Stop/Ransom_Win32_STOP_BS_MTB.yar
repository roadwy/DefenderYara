
rule Ransom_Win32_STOP_BS_MTB{
	meta:
		description = "Ransom:Win32/STOP.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 00 3a 00 5c 00 64 00 6f 00 63 00 5c 00 6d 00 79 00 20 00 77 00 6f 00 72 00 6b 00 20 00 28 00 63 00 2b 00 2b 00 29 00 5c 00 5f 00 67 00 69 00 74 00 5c 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 5c 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 77 00 69 00 6e 00 61 00 70 00 69 00 5c 00 53 00 61 00 6c 00 73 00 61 00 32 00 30 00 2e 00 69 00 6e 00 6c 00 } //01 00  e:\doc\my work (c++)\_git\encryption\encryptionwinapi\Salsa20.inl
		$a_01_1 = {6e 73 31 2e 6b 72 69 73 74 6f 6e 2e 75 67 } //01 00  ns1.kriston.ug
		$a_01_2 = {6e 73 32 2e 63 68 61 6c 65 6b 69 6e 2e 75 67 } //01 00  ns2.chalekin.ug
		$a_01_3 = {6e 73 33 2e 75 6e 61 6c 65 6c 61 74 68 2e 75 67 } //01 00  ns3.unalelath.ug
		$a_01_4 = {6e 73 34 2e 61 6e 64 72 6f 6d 61 74 68 2e 75 67 } //00 00  ns4.andromath.ug
	condition:
		any of ($a_*)
 
}