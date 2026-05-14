
rule Trojan_Win64_Convagent_SXF_MTB{
	meta:
		description = "Trojan:Win64/Convagent.SXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 b8 8a ba 71 12 b4 83 d2 dc 48 89 44 24 ?? 48 8b 44 24 ?? 48 89 44 24 ?? 48 b8 61 91 2c 5b a5 ce 58 d0 48 89 44 24 ?? 48 8b 44 24 ?? 48 89 44 24 ?? 49 b8 cf c2 18 66 e4 f1 bd bf } //30
		$a_01_1 = {33 db 48 8b 03 48 8b cb ff 10 48 8b 03 ba 01 00 00 00 48 8b cb ff 50 08 b9 10 00 00 00 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*10) >=40
 
}