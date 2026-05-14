
rule Trojan_Win64_MintStone_A_dha{
	meta:
		description = "Trojan:Win64/MintStone.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 61 70 70 5f 62 6f 75 6e 64 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 22 3a 22 } //1 "app_bound_encrypted_key":"
		$a_01_1 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 4c 6f 63 61 6c 20 53 74 61 74 65 } //1 \Google\Chrome\User Data\Local State
		$a_01_2 = {64 61 74 61 65 78 63 68 61 6e 67 65 2e 64 6c 6c } //1 dataexchange.dll
		$a_01_3 = {49 6e 6a 65 63 74 54 6f 43 68 72 6f 6d 65 } //1 InjectToChrome
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}