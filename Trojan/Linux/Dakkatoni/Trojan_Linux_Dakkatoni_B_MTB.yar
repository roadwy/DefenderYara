
rule Trojan_Linux_Dakkatoni_B_MTB{
	meta:
		description = "Trojan:Linux/Dakkatoni.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {62 cc b0 72 a5 23 bd 13 d7 14 35 b9 67 45 8e 61 eb f1 9d 0e 8f 21 69 e6 78 01 ba 7e e6 33 eb 0a 85 c3 dc 81 3c 4d 42 1e 84 b1 e7 ab } //1
		$a_00_1 = {88 dd c7 3b 19 69 78 86 ce be 1c 97 63 a8 f2 33 f7 46 25 d3 81 fe 16 4f 00 8d 47 fc b5 1f f9 7a 66 f2 8a 5a 4b 63 4d b4 e5 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}