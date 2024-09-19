
rule Trojan_MacOS_Amos_W_MTB{
	meta:
		description = "Trojan:MacOS/Amos.W!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 4c 02 02 48 83 c0 02 0f b6 4c 18 01 32 0d 85 57 00 00 f6 85 60 fd ff ff 01 4c 89 ea 74 ?? 48 8b 95 70 fd ff ff 88 4c 02 01 48 3d ae 2d 00 00 74 ?? 0f b6 4c 18 02 32 0d 5b 57 00 00 f6 85 60 fd ff ff 01 4c 89 ea } //1
		$a_03_1 = {49 8b 4e 78 be 01 00 00 00 48 89 d7 4c 89 fa e8 f7 07 00 00 48 89 c1 b8 ff ff ff ff 4c 39 f9 0f 85 ?? ?? ?? ?? 4d 89 6e 30 4d 89 6e 28 4d 89 66 38 31 c0 83 fb ff 0f 45 c3 e9 1e ?? ?? ?? 89 5d bc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}