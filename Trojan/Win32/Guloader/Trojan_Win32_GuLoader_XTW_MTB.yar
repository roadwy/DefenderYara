
rule Trojan_Win32_GuLoader_XTW_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.XTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {7d 03 55 40 [0-0a] 60 e4 eb } //1
		$a_03_1 = {8b 3a d9 f6 [0-09] eb } //1
		$a_03_2 = {31 df de f7 [0-09] eb } //1
		$a_03_3 = {01 3a 66 0f [0-0a] eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}