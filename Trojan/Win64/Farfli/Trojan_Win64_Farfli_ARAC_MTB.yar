
rule Trojan_Win64_Farfli_ARAC_MTB{
	meta:
		description = "Trojan:Win64/Farfli.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 10 48 8d 40 01 80 f1 60 88 48 ff 48 83 eb 01 75 ec } //3
		$a_80_1 = {5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c } //\Chrome\User Data\Default\  1
		$a_80_2 = {5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c } //\Edge\User Data\Default\  1
	condition:
		((#a_01_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}