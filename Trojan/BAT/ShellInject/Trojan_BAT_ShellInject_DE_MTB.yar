
rule Trojan_BAT_ShellInject_DE_MTB{
	meta:
		description = "Trojan:BAT/ShellInject.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_81_0 = {24 39 37 39 65 62 31 63 30 2d 37 66 39 32 2d 34 38 38 61 2d 62 61 34 61 2d 65 61 32 30 66 35 38 62 31 63 33 38 } //10 $979eb1c0-7f92-488a-ba4a-ea20f58b1c38
		$a_81_1 = {2f 76 33 2f 75 70 6c 6f 61 64 3f 75 75 69 64 3d 7b 30 7d 26 69 6e 64 65 78 3d 7b 31 7d 26 70 61 72 65 6e 74 3d 7b 32 7d 26 75 70 6c 6f 61 64 4b 65 79 3d 7b 33 7d 26 68 61 73 68 3d 7b 34 7d } //1 /v3/upload?uuid={0}&index={1}&parent={2}&uploadKey={3}&hash={4}
		$a_81_2 = {2f 64 65 6c 65 74 65 2f 70 65 72 6d 61 6e 65 6e 74 } //1 /delete/permanent
		$a_81_3 = {7b 22 6e 61 6d 65 22 3a 22 } //1 {"name":"
		$a_81_4 = {45 6e 63 72 79 70 74 65 64 4d 65 73 73 61 67 65 } //1 EncryptedMessage
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}