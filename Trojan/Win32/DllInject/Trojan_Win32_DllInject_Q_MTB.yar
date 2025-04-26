
rule Trojan_Win32_DllInject_Q_MTB{
	meta:
		description = "Trojan:Win32/DllInject.Q!MTB,SIGNATURE_TYPE_PEHSTR,13 00 13 00 04 00 00 "
		
	strings :
		$a_01_0 = {88 45 ff 0f b6 4d ff c1 f9 06 0f b6 55 ff c1 e2 02 0b ca 88 4d ff 0f b6 45 ff 83 e8 27 88 45 ff 0f b6 4d ff 81 f1 ca 00 00 00 88 4d ff } //10
		$a_01_1 = {6d 63 64 65 64 78 78 64 69 75 } //3 mcdedxxdiu
		$a_01_2 = {52 65 76 6f 6b 65 42 69 6e 64 53 74 61 74 75 73 43 61 6c 6c 62 61 63 6b } //3 RevokeBindStatusCallback
		$a_01_3 = {55 72 6c 4d 6b 47 65 74 53 65 73 73 69 6f 6e 4f 70 74 69 6f 6e } //3 UrlMkGetSessionOption
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=19
 
}