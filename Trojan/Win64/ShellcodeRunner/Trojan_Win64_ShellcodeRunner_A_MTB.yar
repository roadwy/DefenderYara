
rule Trojan_Win64_ShellcodeRunner_A_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 2d b7 0d 00 00 48 8d be 00 f0 ff ff bb 00 10 00 00 50 49 89 e1 41 b8 04 00 00 00 48 89 da 48 89 f9 48 83 ec 20 ff d5 48 8d 87 af 01 00 00 80 20 7f 80 60 28 7f 4c 8d 4c 24 20 4d 8b 01 48 89 da 48 89 f9 ff d5 } //2
		$a_01_1 = {53 56 57 55 48 8d 35 aa ef c0 ff 48 8d be db 0f f1 ff 48 8d 87 9c 41 4d 00 ff 30 c7 00 5c 24 97 9c 50 57 31 db 31 c9 48 83 cd ff e8 50 00 00 00 01 db 74 02 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}