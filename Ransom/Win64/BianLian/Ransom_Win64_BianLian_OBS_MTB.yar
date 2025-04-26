
rule Ransom_Win64_BianLian_OBS_MTB{
	meta:
		description = "Ransom:Win64/BianLian.OBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 74 61 72 74 69 6e 67 20 42 69 61 6e 4c 69 61 6e 20 65 6d 75 6c 61 74 69 6f 6e } //1 Starting BianLian emulation
		$a_81_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 72 75 6e 63 61 6c 63 2e 64 6c 6c 2c 65 6d 70 74 79 7a 69 70 } //2 rundll32.exe runcalc.dll,emptyzip
		$a_81_2 = {74 72 65 6c 6c 69 78 2e 64 69 67 69 74 61 6c } //2 trellix.digital
		$a_81_3 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e 20 50 61 79 20 74 68 65 20 72 61 6e 73 6f 6d 20 74 6f 20 67 65 74 20 74 68 65 6d 20 62 61 63 6b } //1 All your files have been encrypted. Pay the ransom to get them back
		$a_01_4 = {4c 6f 6f 6b 20 61 74 20 74 68 69 73 20 69 6e 73 74 72 75 63 74 69 6f 6e 2e 74 78 74 } //1 Look at this instruction.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}