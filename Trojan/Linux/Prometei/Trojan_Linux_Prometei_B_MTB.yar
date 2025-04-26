
rule Trojan_Linux_Prometei_B_MTB{
	meta:
		description = "Trojan:Linux/Prometei.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {36 44 4e 67 b1 be 50 35 04 99 44 64 48 5b 2d 79 b4 81 ce f7 c5 16 ac 34 9f ce 4b ef 28 f0 26 56 fd cb 8f c0 c0 08 df 04 a8 dd f0 bc eb 68 ee 42 } //1
		$a_00_1 = {43 40 a3 46 f3 4d a7 40 66 64 cb 20 2f d0 f3 bc b3 55 0a 2e 36 5c 68 11 16 93 01 39 c6 52 8e fc bd 60 77 93 f2 08 c3 c6 2a 34 9b 47 35 df 8c 78 2f e7 a0 86 44 cc 3e a4 2b 0d 22 4f 60 83 92 af } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}