
rule Trojan_Win64_FaceLight_B_dha{
	meta:
		description = "Trojan:Win64/FaceLight.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_40_0 = {c9 ba 00 00 a0 00 41 b8 00 10 00 00 44 8d 49 04 48 89 05 } //5
		$a_33_1 = {41 b8 00 00 a0 00 48 8b c8 48 8b f8 e8 00 00 5d 04 00 00 f7 d8 06 80 5c 28 00 00 f8 d8 06 80 00 00 01 00 08 00 12 00 ac 21 47 75 4c 6f 61 64 65 72 2e 52 53 42 21 4d 54 42 00 00 05 40 05 82 70 } //3840
	condition:
		((#a_40_0  & 1)*5+(#a_33_1  & 1)*3840) >=10
 
}