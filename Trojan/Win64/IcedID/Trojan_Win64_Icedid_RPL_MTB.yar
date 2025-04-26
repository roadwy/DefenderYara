
rule Trojan_Win64_Icedid_RPL_MTB{
	meta:
		description = "Trojan:Win64/Icedid.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 c7 84 24 18 03 00 00 6b 00 66 c7 84 24 1a 03 00 00 65 00 66 c7 84 24 1c 03 00 00 72 00 66 c7 84 24 1e 03 00 00 6e 00 66 c7 84 24 20 03 00 00 65 00 66 c7 84 24 22 03 00 00 6c 00 66 c7 84 24 24 03 00 00 33 00 66 c7 84 24 26 03 00 00 32 00 } //1
		$a_03_1 = {41 f7 ec c1 fa ?? 8b c2 c1 e8 ?? 03 d0 49 63 c4 41 83 c4 ?? 48 63 ca 48 6b c9 ?? 48 03 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}