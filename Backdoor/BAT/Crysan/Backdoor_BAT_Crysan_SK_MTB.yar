
rule Backdoor_BAT_Crysan_SK_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {35 79 70 6b 64 68 65 73 66 79 68 62 65 6b 77 76 72 32 6c 74 66 71 62 77 77 6a 6d 70 68 6d 79 61 } //2 5ypkdhesfyhbekwvr2ltfqbwwjmphmya
		$a_81_1 = {43 6c 69 65 6e 74 2e 65 78 65 } //1 Client.exe
		$a_81_2 = {53 74 75 62 2e 65 78 65 } //1 Stub.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}