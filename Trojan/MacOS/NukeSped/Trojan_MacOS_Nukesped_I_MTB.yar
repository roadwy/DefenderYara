
rule Trojan_MacOS_Nukesped_I_MTB{
	meta:
		description = "Trojan:MacOS/Nukesped.I!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 89 e0 31 c9 ?? ?? ?? ?? ?? ?? ?? 89 ce 83 e6 1f 8a 14 3e 30 14 0b 48 ff c1 48 39 c8 } //1
		$a_01_1 = {8b 4d ec 89 ce c1 ee 02 83 e6 3f 42 8a 34 06 89 c7 40 88 34 3a c1 e1 04 83 e1 30 44 89 ce c1 ee 04 83 e6 0f 48 09 ce 41 8a 0c 30 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}