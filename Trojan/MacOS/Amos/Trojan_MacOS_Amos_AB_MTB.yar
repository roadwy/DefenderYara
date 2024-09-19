
rule Trojan_MacOS_Amos_AB_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AB!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 06 40 f9 9f 02 15 eb 68 ?? ?? ?? 02 ?? ?? ?? a0 02 67 9e 00 58 20 0e 00 38 30 2e 08 00 26 1e 69 0e 40 f9 20 01 23 9e 61 22 40 bd 00 18 21 1e 00 00 29 9e bf 0e 00 f1 02 29 41 fa 69 ?? ?? ?? 19 04 00 94 } //1
		$a_03_1 = {f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 f3 03 00 aa 28 04 00 f1 61 ?? ?? ?? 54 00 80 52 07 ?? ?? ?? f4 03 01 aa 3f 00 08 ea 80 ?? ?? ?? e0 03 14 aa 2b 04 00 94 f4 03 00 aa } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}