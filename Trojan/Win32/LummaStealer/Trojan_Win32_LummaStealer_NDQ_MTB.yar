
rule Trojan_Win32_LummaStealer_NDQ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {4c 4f 47 53 31 32 2d 2d 6d 69 6e 65 63 72 61 66 } //2 LOGS12--minecraf
		$a_81_1 = {4d 78 53 36 76 34 62 74 56 33 75 74 7a 36 63 6d 69 62 68 61 6e 4e 6e 38 57 53 36 48 49 62 73 69 43 6d 74 37 39 39 4a 56 } //1 MxS6v4btV3utz6cmibhanNn8WS6HIbsiCmt799JV
		$a_01_2 = {89 dd f7 d5 21 cd 89 e8 0f af ea 89 ca f7 d2 21 da 8b 1c 24 f7 d3 21 fb 0f af da f7 e2 } //1
		$a_01_3 = {f7 e6 01 ca 0f af f5 01 d6 03 44 24 1c 11 de 03 44 24 04 11 fe 89 f7 c1 ef 15 31 f7 89 f3 0f a4 c3 0b 31 c3 } //1
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}