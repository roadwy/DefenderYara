
rule Trojan_Win64_Muddywater_GVD_MTB{
	meta:
		description = "Trojan:Win64/Muddywater.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 8d 49 01 f7 eb 8b cb ff c3 d1 fa 8b c2 c1 e8 1f 03 d0 8d 04 92 2b c8 48 63 c1 42 0f b6 4c 0c 4f 42 2a 0c 10 43 88 4c 01 ff 83 fb 3b 72 cc } //2
		$a_01_1 = {5c 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 \logins.json
		$a_01_2 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
		$a_01_3 = {5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \Default\Login Data
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}