
rule Trojan_Win64_TrickbotMshare_A_MTB{
	meta:
		description = "Trojan:Win64/TrickbotMshare.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {37 63 38 44 68 78 57 58 6a 45 72 54 37 43 2f 7a 37 63 65 } //1 7c8DhxWXjErT7C/z7ce
		$a_01_1 = {34 50 6a 2b 2f 44 39 6f 4a 50 34 5a 4a 44 79 6f 47 32 6a 2b 2f 44 39 6f 4a 63 37 71 47 32 6a 31 4a 44 34 4d 75 4c 59 4c 49 45 2b 6f 56 67 35 } //1 4Pj+/D9oJP4ZJDyoG2j+/D9oJc7qG2j1JD4MuLYLIE+oVg5
		$a_01_2 = {50 44 50 71 49 50 6a 2b 2f 44 39 6f 4a 47 6a 63 49 47 34 4c 73 77 6a 6f } //1 PDPqIPj+/D9oJGjcIG4Lswjo
		$a_01_3 = {49 67 59 4d 6d 77 34 64 2f 43 57 7a 6d 77 39 61 } //1 IgYMmw4d/CWzmw9a
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}