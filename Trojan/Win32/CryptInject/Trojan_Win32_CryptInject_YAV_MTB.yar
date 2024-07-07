
rule Trojan_Win32_CryptInject_YAV_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 50 53 e8 01 00 00 00 cc } //10
		$a_01_1 = {58 89 c3 40 2d 00 a0 26 00 2d 00 82 0c 10 05 f7 81 0c 10 80 3b cc } //1
		$a_01_2 = {85 c9 74 0a 31 06 01 1e 83 c6 04 49 eb } //10
		$a_01_3 = {e8 00 00 00 00 58 05 58 00 00 00 80 38 e9 75 13 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=31
 
}