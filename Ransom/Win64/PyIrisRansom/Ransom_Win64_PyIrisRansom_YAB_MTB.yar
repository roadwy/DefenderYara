
rule Ransom_Win64_PyIrisRansom_YAB_MTB{
	meta:
		description = "Ransom:Win64/PyIrisRansom.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 52 49 53 20 52 41 4e 53 4f 4d 57 41 52 45 20 47 52 4f 55 50 } //10 IRIS RANSOMWARE GROUP
		$a_01_1 = {61 74 74 65 6d 70 74 20 74 6f 20 72 65 73 74 61 72 74 2c 20 73 68 75 74 20 64 6f 77 6e } //1 attempt to restart, shut down
		$a_01_2 = {63 6f 6d 70 6c 65 74 65 6c 79 20 6c 6f 63 6b 65 64 20 64 6f 77 6e } //1 completely locked down
		$a_01_3 = {63 6f 6d 70 6c 65 74 65 20 61 63 63 65 73 73 20 74 6f 20 45 56 45 52 59 54 48 49 4e 47 } //1 complete access to EVERYTHING
		$a_01_4 = {70 72 69 76 61 63 79 20 6e 6f 20 6c 6f 6e 67 65 72 20 65 78 69 73 74 73 } //1 privacy no longer exists
		$a_01_5 = {66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 70 65 72 6d 61 6e 65 6e 74 6c 79 20 64 65 73 74 72 6f 79 65 64 } //1 files will be permanently destroyed
		$a_01_6 = {6e 6f 20 77 61 79 20 74 6f 20 72 65 63 6f 76 65 72 20 74 68 65 6d } //1 no way to recover them
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}