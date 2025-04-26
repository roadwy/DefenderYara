
rule Trojan_Win32_ZgRAT_NG_MTB{
	meta:
		description = "Trojan:Win32/ZgRAT.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 8d 94 fd ff ff ?? ?? ?? ?? 2b c1 33 d0 0f af 95 94 fd ff ff 89 95 14 e1 ff ff 8b 95 14 e1 ff ff 89 95 10 e1 ff ff 83 bd 10 e1 ff ff 00 0f 86 f5 04 00 00 52 } //3
		$a_01_1 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 57 } //1 InternetOpenUrlW
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}