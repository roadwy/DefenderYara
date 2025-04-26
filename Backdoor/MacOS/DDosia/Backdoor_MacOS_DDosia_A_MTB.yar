
rule Backdoor_MacOS_DDosia_A_MTB{
	meta:
		description = "Backdoor:MacOS/DDosia.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {90 0b 40 f9 ff 63 30 eb c9 03 00 54 fe 0f 1e f8 fd 83 1f f8 fd 23 00 d1 1b 29 00 90 61 8f 42 f9 1b 29 00 90 62 8b 42 f9 1f 00 01 eb 2a 01 00 54 42 02 00 54 43 10 00 8b 61 04 40 f9 03 ec 7c d3 40 68 63 f8 fd fb 7f a9 ff 83 00 91 } //1
		$a_01_1 = {3f 00 00 f1 c9 00 00 54 40 00 40 f9 41 04 40 f9 fd fb 7f a9 ff 83 00 91 c0 03 5f d6 e0 03 1f aa e1 03 00 aa 33 98 01 94 36 98 01 94 1f 20 03 d5 e0 07 00 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}