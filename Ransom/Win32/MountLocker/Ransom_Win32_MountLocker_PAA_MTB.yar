
rule Ransom_Win32_MountLocker_PAA_MTB{
	meta:
		description = "Ransom:Win32/MountLocker.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 00 6e 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 63 00 68 00 65 00 63 00 6b 00 2e 00 64 00 62 00 6c 00 5f 00 72 00 75 00 6e 00 20 00 3e 00 20 00 65 00 78 00 69 00 73 00 74 00 73 00 } //01 00  unlocker.check.dbl_run > exists
		$a_01_1 = {52 00 45 00 41 00 44 00 4d 00 45 00 5f 00 54 00 4f 00 5f 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  README_TO_DECRYPT.html
		$a_01_2 = {54 00 6f 00 74 00 61 00 6c 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  Total decrypted
		$a_01_3 = {4b 00 49 00 4c 00 4c 00 20 00 50 00 52 00 4f 00 43 00 45 00 53 00 53 00 } //01 00  KILL PROCESS
		$a_01_4 = {4b 00 49 00 4c 00 4c 00 20 00 53 00 45 00 52 00 56 00 49 00 43 00 45 00 } //01 00  KILL SERVICE
		$a_01_5 = {2e 00 71 00 75 00 61 00 6e 00 74 00 75 00 6d 00 } //00 00  .quantum
	condition:
		any of ($a_*)
 
}