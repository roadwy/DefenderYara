
rule Trojan_MacOS_Amos_I_MTB{
	meta:
		description = "Trojan:MacOS/Amos.I!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 4d b8 30 4c 05 b8 48 ff c0 48 83 f8 03 75 f0 44 0f b6 ad 58 ff ff ff 44 89 eb 80 e3 01 74 52 4c 8b ad 60 ff ff ff eb 4c } //2
		$a_01_1 = {8a 8d 68 ff ff ff 30 8c 05 68 ff ff ff 48 ff c0 48 83 f8 03 75 ea 0f b6 1a f6 c3 01 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}