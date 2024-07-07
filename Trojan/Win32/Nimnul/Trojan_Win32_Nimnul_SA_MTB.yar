
rule Trojan_Win32_Nimnul_SA_MTB{
	meta:
		description = "Trojan:Win32/Nimnul.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 04 88 d5 fb da 4f 33 15 90 01 04 33 fc 8b 7d f0 89 1d 90 01 04 8b 75 f8 83 c1 01 81 f9 6a 07 00 00 0f 82 d6 ff ff ff 90 00 } //3
		$a_01_1 = {58 71 64 6a 7a 74 62 2e 64 6c 6c } //2 Xqdjztb.dll
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}