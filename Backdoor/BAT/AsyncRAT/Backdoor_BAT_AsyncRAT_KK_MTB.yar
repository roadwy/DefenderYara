
rule Backdoor_BAT_AsyncRAT_KK_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 34 61 32 66 38 66 62 36 2d 31 30 37 37 2d 34 36 39 61 2d 39 32 34 36 2d 37 33 36 65 36 61 66 65 38 64 61 31 } //4 $4a2f8fb6-1077-469a-9246-736e6afe8da1
		$a_01_1 = {43 6c 69 65 6e 74 2e 65 78 65 } //3 Client.exe
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //2 GetExecutingAssembly
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=9
 
}