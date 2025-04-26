
rule Trojan_MacOS_Amos_Y_MTB{
	meta:
		description = "Trojan:MacOS/Amos.Y!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 d6 48 c1 ee 3e 48 31 d6 49 0f af f7 48 01 ce 48 ff ce 48 89 b4 cd a8 ef ff ff 48 81 f9 38 01 00 00 74 ?? ?? ?? ?? ?? 48 89 f7 48 c1 ef 3e 48 31 f7 49 0f af ff 48 01 fa 48 01 cf 48 89 bc cd b0 ef ff ff 48 83 c0 02 48 83 c1 02 } //1
		$a_01_1 = {48 89 c2 48 c1 ea 1c 81 e2 00 ff 00 00 48 09 ca 48 89 c1 48 c1 e9 18 81 e1 00 00 ff 00 48 09 d1 48 89 c2 48 c1 ea 14 81 e2 00 00 00 ff 48 09 ca 48 89 c1 48 c1 e9 10 49 b8 00 00 00 00 ff 00 00 00 4c 21 c1 48 89 c6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}