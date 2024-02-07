
rule Trojan_Win64_Convagent_BO_MTB{
	meta:
		description = "Trojan:Win64/Convagent.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {31 34 34 2e 31 37 32 2e 38 33 2e 31 33 2f 41 67 65 6e 74 36 34 2e 62 69 6e } //05 00  144.172.83.13/Agent64.bin
		$a_01_1 = {72 6f 6f 6b 62 6f 6c 69 6e 2e 6e 65 74 2f 41 67 65 6e 74 36 34 2e 62 69 6e } //05 00  rookbolin.net/Agent64.bin
		$a_01_2 = {33 38 2e 31 30 38 2e 31 31 39 2e 31 32 31 2f 41 67 65 6e 74 36 34 2e 62 69 6e } //01 00  38.108.119.121/Agent64.bin
		$a_01_3 = {43 6f 6e 76 65 72 74 42 6d 70 } //01 00  ConvertBmp
		$a_01_4 = {43 6f 6e 76 65 72 74 4a 70 67 } //01 00  ConvertJpg
		$a_01_5 = {43 6f 6e 76 65 72 74 54 69 66 66 } //00 00  ConvertTiff
	condition:
		any of ($a_*)
 
}