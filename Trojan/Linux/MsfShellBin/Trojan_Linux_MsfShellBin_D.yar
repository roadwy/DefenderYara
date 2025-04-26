
rule Trojan_Linux_MsfShellBin_D{
	meta:
		description = "Trojan:Linux/MsfShellBin.D,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 db 53 89 e7 6a 10 54 57 53 89 e1 b3 07 ff 01 6a 66 58 cd 80 66 81 7f 02 ?? ?? 75 f1 5b 6a 02 59 b0 3f cd 80 49 79 f9 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 } //1
		$a_03_1 = {48 31 ff 48 31 db b3 18 48 29 dc 48 8d 14 24 48 c7 02 10 00 00 00 48 8d 74 24 08 6a 34 58 0f 05 48 ff c7 66 81 7e 02 ?? ?? 75 f0 48 ff cf 6a 02 5e 6a 21 58 0f 05 48 ff ce 79 f6 48 89 f3 bb 41 2f 73 68 b8 2f 62 69 6e 48 c1 eb 08 48 c1 e3 20 48 09 d8 50 48 89 e7 48 31 f6 48 89 f2 6a 3b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}