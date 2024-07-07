
rule Ransom_Win64_FileCoder_AG_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {2f 77 69 70 65 } //1 /wipe
		$a_01_1 = {56 75 6c 6b 61 49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 VulkaInternetOpenA
		$a_01_2 = {56 75 6c 6b 61 46 69 6e 64 46 69 72 73 74 46 69 6c 65 57 } //1 VulkaFindFirstFileW
		$a_81_3 = {47 45 4e 42 4f 54 49 44 20 62 65 67 69 6e } //1 GENBOTID begin
		$a_81_4 = {53 4d 42 46 41 53 54 20 62 65 67 69 6e } //1 SMBFAST begin
		$a_81_5 = {70 72 65 20 46 49 4e 44 46 49 4c 45 53 20 31 20 62 65 67 69 6e } //1 pre FINDFILES 1 begin
		$a_81_6 = {57 41 52 4e 49 4e 47 2e 54 58 54 } //1 WARNING.TXT
		$a_81_7 = {4b 49 4c 4c 50 52 20 62 65 67 69 6e } //1 KILLPR begin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}