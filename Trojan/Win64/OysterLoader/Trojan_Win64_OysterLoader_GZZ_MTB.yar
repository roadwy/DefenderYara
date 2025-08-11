
rule Trojan_Win64_OysterLoader_GZZ_MTB{
	meta:
		description = "Trojan:Win64/OysterLoader.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 ba ?? ?? ?? ?? 31 c9 41 b8 00 30 00 00 41 b9 40 00 00 00 ff 15 } //5
		$a_01_1 = {41 ff d6 48 89 c7 48 89 f1 ba 02 00 00 00 41 ff d7 } //5
		$a_01_2 = {41 ff d7 48 89 c7 48 89 f1 ba 02 00 00 00 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}