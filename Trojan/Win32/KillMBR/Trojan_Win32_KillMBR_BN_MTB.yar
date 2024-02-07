
rule Trojan_Win32_KillMBR_BN_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 44 72 69 76 65 30 20 46 61 69 6c 65 64 21 } //01 00  Open Drive0 Failed!
		$a_01_1 = {72 65 61 64 20 6d 62 72 20 46 61 69 6c 65 64 21 } //01 00  read mbr Failed!
		$a_01_2 = {41 6c 72 65 61 64 79 20 69 6e 66 65 63 74 65 64 21 } //01 00  Already infected!
		$a_01_3 = {77 72 69 74 65 20 62 61 63 6b 75 70 20 6d 62 72 20 46 61 69 6c 65 64 21 } //01 00  write backup mbr Failed!
		$a_01_4 = {57 72 69 74 65 20 6f 72 69 67 69 6e 61 6c 65 20 6d 62 72 21 } //01 00  Write originale mbr!
		$a_01_5 = {57 72 69 74 65 20 4d 42 52 20 4f 4b 21 } //00 00  Write MBR OK!
	condition:
		any of ($a_*)
 
}