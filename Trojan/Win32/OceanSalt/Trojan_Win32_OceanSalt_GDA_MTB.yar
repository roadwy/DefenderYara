
rule Trojan_Win32_OceanSalt_GDA_MTB{
	meta:
		description = "Trojan:Win32/OceanSalt.GDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {b8 00 20 41 00 80 30 0f 40 3d 56 4e 41 00 7e f5 } //01 00 
		$a_01_1 = {32 37 2e 31 30 32 2e 31 31 32 2e 31 37 39 } //01 00  27.102.112.179
		$a_01_2 = {5c 50 75 62 6c 69 63 5c 56 69 64 65 6f 73 5c 74 65 6d 70 2e 6c 6f 67 } //01 00  \Public\Videos\temp.log
		$a_01_3 = {53 52 51 68 61 72 79 41 68 4c 69 62 72 68 4c 6f 61 64 54 53 } //00 00  SRQharyAhLibrhLoadTS
	condition:
		any of ($a_*)
 
}