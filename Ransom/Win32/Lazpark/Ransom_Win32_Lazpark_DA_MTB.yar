
rule Ransom_Win32_Lazpark_DA_MTB{
	meta:
		description = "Ransom:Win32/Lazpark.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 69 73 20 70 65 6e 65 74 72 61 74 65 64 } //01 00  Your network is penetrated
		$a_81_1 = {6c 61 7a 70 61 72 6b 69 6e 67 2d 6d 65 73 73 61 67 65 2e 74 78 74 } //01 00  lazparking-message.txt
		$a_81_2 = {72 61 6e 73 6f 6d 77 61 72 65 } //01 00  ransomware
		$a_81_3 = {43 48 41 43 48 41 32 30 } //01 00  CHACHA20
		$a_81_4 = {66 61 6b 65 2e 70 64 62 } //00 00  fake.pdb
	condition:
		any of ($a_*)
 
}