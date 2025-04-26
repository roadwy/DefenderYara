
rule Trojan_BAT_FormBook_SMI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.SMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {24 63 32 30 38 34 34 66 64 2d 64 64 37 63 2d 34 66 33 38 2d 61 37 39 63 2d 30 39 38 39 34 65 66 32 30 39 36 33 } //1 $c20844fd-dd7c-4f38-a79c-09894ef20963
		$a_81_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 74 69 6d 65 6f 75 74 20 32 20 26 20 73 74 61 72 74 } //1 cmd.exe /c timeout 2 & start
		$a_81_2 = {5a 54 5f 52 41 54 5f 4c 6f 61 64 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 ZT_RAT_Loader.Properties.Resources
		$a_81_3 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}