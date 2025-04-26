
rule Trojan_MacOS_PassSteal_B_MTB{
	meta:
		description = "Trojan:MacOS/PassSteal.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 83 00 d1 fd 7b 01 a9 fd 43 00 91 e9 03 00 aa e9 07 00 f9 e1 03 00 f9 28 00 40 f9 28 01 00 f9 28 04 40 f9 20 05 40 f9 28 05 00 f9 b0 01 00 94 e1 03 40 f9 e9 07 40 f9 28 08 40 f9 20 09 40 f9 28 09 00 f9 ea 00 00 94 e0 07 40 f9 fd 7b 41 a9 ff 83 00 91 } //1
		$a_01_1 = {fd 7b bf a9 fd 03 00 91 ff 83 01 d1 a8 03 1c f8 a0 83 1a f8 a1 03 1d f8 a2 83 1d f8 a3 03 1e f8 a4 83 1e f8 e8 03 01 aa a8 83 1f f8 e8 03 02 aa a8 03 1f f8 00 00 80 d2 ed 22 00 94 a2 03 5d f8 a1 83 5a f8 a0 83 1b f8 08 80 5f f8 08 21 40 f9 08 fd 40 d3 08 3d 00 91 09 ed 7c 92 a9 03 1b f8 50 00 00 f0 10 4a 40 f9 00 02 3f d6 a9 03 5b f8 e8 03 00 91 00 01 09 eb a0 83 1c f8 1f 00 00 91 48 80 5f f8 08 09 40 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}