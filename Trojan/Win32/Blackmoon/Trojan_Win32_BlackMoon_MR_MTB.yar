
rule Trojan_Win32_BlackMoon_MR_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {3b f0 73 1e 80 66 04 00 83 0e ff 83 66 08 00 c6 46 05 0a a1 80 af 65 00 83 c6 24 05 80 04 00 00 eb } //10
		$a_01_1 = {57 57 57 2e 31 32 47 41 4d 44 48 2e 43 4f 4d } //2 WWW.12GAMDH.COM
		$a_01_2 = {52 65 6d 6f 76 65 50 6c 61 79 65 72 } //1 RemovePlayer
		$a_01_3 = {43 72 65 61 74 65 50 6c 61 79 65 72 } //1 CreatePlayer
		$a_01_4 = {47 65 74 50 6c 61 79 53 74 61 74 65 } //1 GetPlayState
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=15
 
}