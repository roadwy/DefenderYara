
rule Trojan_Win32_Coinminer_MA_MTB{
	meta:
		description = "Trojan:Win32/Coinminer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {3a 5c 41 6e 76 69 72 4c 61 62 5c 4d 69 6e 69 6e 67 5f 66 72 61 6d 65 77 6f 72 6b 2e 70 64 62 } //03 00  :\AnvirLab\Mining_framework.pdb
		$a_01_1 = {53 00 61 00 6d 00 61 00 65 00 6c 00 4c 00 6f 00 76 00 65 00 73 00 4d 00 65 00 } //01 00  SamaelLovesMe
		$a_01_2 = {6c 61 73 74 5f 6d 69 6e 65 72 5f 6c 69 6e 6b } //01 00  last_miner_link
		$a_01_3 = {74 6f 6f 6c 73 2f 52 65 67 57 72 69 74 65 72 2e 65 78 65 2e 72 61 75 6d 5f 65 6e 63 72 79 70 74 65 64 } //01 00  tools/RegWriter.exe.raum_encrypted
		$a_01_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 56 69 64 65 6f 43 6f 6e 74 72 6f 6c 6c 65 72 } //01 00  SELECT * FROM Win32_VideoController
		$a_01_5 = {52 00 4f 00 4f 00 54 00 5c 00 43 00 49 00 4d 00 56 00 32 00 } //00 00  ROOT\CIMV2
	condition:
		any of ($a_*)
 
}