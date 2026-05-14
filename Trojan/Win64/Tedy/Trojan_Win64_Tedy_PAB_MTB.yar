
rule Trojan_Win64_Tedy_PAB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 53 48 8d 15 e6 2f 00 00 48 8d 8c 24 80 02 00 00 ff 15 78 2c 00 00 48 85 c0 75 39 48 8d 15 dc 2f 00 00 48 8d 8c 24 80 02 00 00 ff 15 5e 2c 00 00 48 85 c0 75 1f 48 8d 15 d2 2f 00 00 48 8d 8c 24 80 02 00 00 ff 15 44 2c 00 00 48 f7 d8 } //3
		$a_81_1 = {5b 45 52 52 5d 20 49 6e 6a 65 63 74 20 66 61 69 6c 65 64 20 28 25 64 29 2e 20 52 75 6e 20 61 73 20 41 64 6d 69 6e 2e } //1 [ERR] Inject failed (%d). Run as Admin.
		$a_81_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_01_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}