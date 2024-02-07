
rule Ransom_Win32_Crylock_PAA_MTB{
	meta:
		description = "Ransom:Win32/Crylock.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 2f 45 4e 44 20 50 52 4f 43 45 53 53 45 53 20 57 48 49 54 45 20 4c 49 53 54 5c 5c 5c } //01 00  ///END PROCESSES WHITE LIST\\\
		$a_01_1 = {2f 2f 2f 45 4e 44 20 55 4e 45 4e 43 52 59 50 54 20 46 49 4c 45 53 20 4c 49 53 54 5c 5c 5c } //01 00  ///END UNENCRYPT FILES LIST\\\
		$a_01_2 = {2f 63 20 22 70 69 6e 67 20 30 2e 30 2e 30 2e 30 26 64 65 6c 20 22 } //01 00  /c "ping 0.0.0.0&del "
		$a_81_3 = {68 6f 77 5f 74 6f 5f 64 65 63 72 79 70 74 2e 68 74 61 } //00 00  how_to_decrypt.hta
	condition:
		any of ($a_*)
 
}