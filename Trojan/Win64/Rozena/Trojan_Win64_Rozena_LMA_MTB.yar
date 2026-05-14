
rule Trojan_Win64_Rozena_LMA_MTB{
	meta:
		description = "Trojan:Win64/Rozena.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {5b 4c 6f 61 64 65 72 5d 20 46 65 74 63 68 69 6e 67 20 62 6f 6f 74 73 74 72 61 70 70 65 72 2e 2e 2e } //1 [Loader] Fetching bootstrapper...
		$a_81_1 = {5b 4c 6f 61 64 65 72 5d 20 46 61 69 6c 65 64 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 70 61 79 6c 6f 61 64 20 66 72 6f 6d 20 55 52 4c 2e } //2 [Loader] Failed to download payload from URL.
		$a_81_2 = {5b 4c 6f 61 64 65 72 5d 20 4d 61 70 70 69 6e 67 20 66 61 69 6c 65 64 } //3 [Loader] Mapping failed
		$a_81_3 = {5b 4c 6f 61 64 65 72 5d 20 50 61 79 6c 6f 61 64 20 6d 61 70 70 65 64 2e } //4 [Loader] Payload mapped.
		$a_81_4 = {5c 72 75 6e 70 65 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 72 75 6e 70 65 } //5 \runpe\x64\Release\runpe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5) >=15
 
}