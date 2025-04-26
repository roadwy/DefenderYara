
rule Backdoor_BAT_Crysan_ARA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {25 00 52 00 6f 00 6f 00 74 00 4b 00 69 00 74 00 25 00 } //2 %RootKit%
		$a_01_1 = {24 34 61 32 66 38 66 62 36 2d 31 30 37 37 2d 34 36 39 61 2d 39 32 34 36 2d 37 33 36 65 36 61 66 65 38 64 61 31 } //3 $4a2f8fb6-1077-469a-9246-736e6afe8da1
		$a_00_2 = {43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //3 Client.exe
		$a_01_3 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_4 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*3+(#a_00_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}