
rule Trojan_Win32_IcedId_SA_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SA!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 74 65 6d 70 5c 66 6f 6f 2e 74 78 74 } //1 C:\temp\foo.txt
		$a_01_1 = {6a 6c 37 43 76 57 6a 38 77 61 45 41 68 33 65 4f 65 33 72 35 30 6b 41 30 6f 6a 7a 68 74 6d 53 4e 61 33 51 32 46 50 7a 6b 62 38 41 54 67 6d 64 4a 72 38 } //2 jl7CvWj8waEAh3eOe3r50kA0ojzhtmSNa3Q2FPzkb8ATgmdJr8
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 55 73 65 72 20 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 Microsoft\windows\CurrentVersion\Explorer\User Shell Folders
		$a_01_3 = {74 00 77 00 37 00 54 00 51 00 74 00 39 00 70 00 4e 00 73 00 74 00 4c 00 37 00 57 00 6e 00 } //1 tw7TQt9pNstL7Wn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}