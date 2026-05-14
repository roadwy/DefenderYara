
rule Ransom_Win64_Gehenna_YBG_MTB{
	meta:
		description = "Ransom:Win64/Gehenna.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 3a } //1 Files encrypted:
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 20 62 79 } //1 encrypted by
		$a_01_2 = {52 45 41 44 4d 45 5f 52 45 53 54 4f 52 45 } //1 README_RESTORE
		$a_01_3 = {47 45 48 45 4e 4e 41 5f 4c 4f 43 4b 45 52 } //1 GEHENNA_LOCKER
		$a_01_4 = {54 65 6d 70 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 Temp\svchost.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}