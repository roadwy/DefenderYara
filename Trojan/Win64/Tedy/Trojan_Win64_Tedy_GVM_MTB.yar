
rule Trojan_Win64_Tedy_GVM_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 48 04 83 e1 07 41 0f b6 0c 0b 32 4c 06 04 41 88 0c 01 48 83 c0 01 4c 39 c0 75 e4 } //2
		$a_01_1 = {73 f5 e4 f3 9d 42 ec 6f e8 b4 86 54 7b 81 85 17 60 61 63 d8 f6 bd 9c 66 86 60 c0 8e ba 73 fe e4 9f 65 b2 87 85 b4 31 48 7d 10 75 d9 56 ab 3c 52 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}