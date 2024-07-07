
rule Trojan_Win64_Cobaltstrike_EB_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c3 31 c0 39 c6 7e 15 48 89 c2 83 e2 07 8a 54 15 00 32 14 07 88 14 03 48 ff c0 eb e7 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win64_Cobaltstrike_EB_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c1 44 8b c0 48 8b 93 f8 00 00 00 48 8b 8b a8 00 00 00 48 2b cf 48 8b 42 50 48 0f af c1 48 89 42 50 49 83 e8 01 75 dd 48 8b 83 d8 00 00 00 8b 88 38 01 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}
rule Trojan_Win64_Cobaltstrike_EB_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 83 c0 01 f7 ed c1 fa 03 8b c2 c1 e8 1f 03 d0 48 63 c5 83 c5 01 48 63 ca 48 6b c9 21 48 03 c8 48 8b 44 24 38 42 0f b6 8c 31 b0 98 04 00 41 32 4c 00 ff 41 88 4c 18 ff } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_Win64_Cobaltstrike_EB_MTB_4{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_81_1 = {75 63 6a 6b 7a 73 6c 69 6a 62 6d 74 64 73 2e 64 6c 6c } //1 ucjkzslijbmtds.dll
		$a_81_2 = {63 76 78 64 65 6d 77 66 6c 66 73 64 78 79 6c 7a 61 } //1 cvxdemwflfsdxylza
		$a_81_3 = {6c 75 71 77 6e 70 70 72 64 74 70 6b 62 66 } //1 luqwnpprdtpkbf
		$a_81_4 = {70 73 63 73 71 73 75 6d 76 66 6f 65 66 6f 75 62 } //1 pscsqsumvfoefoub
		$a_81_5 = {72 71 78 71 6b 77 63 69 68 66 74 7a 61 69 79 70 6b } //1 rqxqkwcihftzaiypk
		$a_81_6 = {67 67 64 66 68 78 75 73 7a 71 66 63 69 6f 2e 64 6c 6c } //1 ggdfhxuszqfcio.dll
		$a_81_7 = {63 72 63 7a 78 76 6b 67 6f 73 6f 6e 6b } //1 crczxvkgosonk
		$a_81_8 = {6f 6a 7a 6c 7a 6a 62 64 75 72 62 6e 68 69 79 77 } //1 ojzlzjbdurbnhiyw
		$a_81_9 = {72 70 69 78 71 62 6f 6d 67 6b 68 63 62 6a 6e } //1 rpixqbomgkhcbjn
		$a_81_10 = {75 62 6c 61 6e 66 6b 6f 61 7a 6e 65 79 75 } //1 ublanfkoazneyu
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=15
 
}