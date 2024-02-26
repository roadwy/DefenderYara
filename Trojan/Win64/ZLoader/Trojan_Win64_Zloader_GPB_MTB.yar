
rule Trojan_Win64_Zloader_GPB_MTB{
	meta:
		description = "Trojan:Win64/Zloader.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 28 72 b3 a3 15 78 e2 91 79 1e ad 31 66 7e b3 57 28 a4 f5 a5 5e da a1 1b 95 b8 8d 49 48 06 90 2f 59 6c fe bd 23 62 a9 73 58 e8 83 } //02 00 
		$a_01_1 = {4d c1 a6 38 72 88 23 3f 72 c8 20 3f 62 78 45 38 de 19 78 30 ea cc 80 33 ca 19 df 3c 95 b0 03 32 } //00 00 
	condition:
		any of ($a_*)
 
}