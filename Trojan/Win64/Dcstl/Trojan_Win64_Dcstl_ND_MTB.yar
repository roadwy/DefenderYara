
rule Trojan_Win64_Dcstl_ND_MTB{
	meta:
		description = "Trojan:Win64/Dcstl.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 8b 03 48 85 c0 74 09 e8 7e ff 00 00 85 c0 75 0b 48 83 c3 08 48 3b df 75 e6 33 c0 } //2
		$a_01_1 = {44 49 53 43 4f 52 44 20 54 4f 4b 45 4e 53 20 43 41 50 54 55 52 45 44 } //1 DISCORD TOKENS CAPTURED
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 20 42 65 74 61 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //1 Microsoft\Edge Beta\User Data\Default\Local Storage\leveldb
		$a_01_3 = {4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 } //1 Mozilla\Firefox\Profiles
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}