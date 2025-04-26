
rule Trojan_Win64_Zenpak_GPA_MTB{
	meta:
		description = "Trojan:Win64/Zenpak.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 69 6d 4b 4b 67 6f 71 69 23 23 } //1 CimKKgoqi##
		$a_01_1 = {73 4b 4b 34 6f 73 43 69 79 23 23 } //1 sKK4osCiy##
		$a_01_2 = {23 4b 4b 4d 77 6f 7a 69 6a 51 4b 4e 49 6f 31 43 6a 57 23 23 } //1 #KKMwozijQKNIo1CjW##
		$a_01_3 = {52 59 70 47 69 6b 63 4b 52 34 70 49 43 23 23 } //1 RYpGikcKR4pIC##
		$a_01_4 = {53 77 70 4c 69 6b 77 4b 54 49 70 4e 43 6b 34 4b 54 6f 70 50 43 6b 23 23 } //3 SwpLikwKTIpNCk4KTopPCk##
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3) >=7
 
}