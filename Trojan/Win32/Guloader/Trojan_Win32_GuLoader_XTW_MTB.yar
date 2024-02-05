
rule Trojan_Win32_GuLoader_XTW_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.XTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {7d 03 55 40 90 02 0a 60 e4 eb 90 00 } //01 00 
		$a_03_1 = {8b 3a d9 f6 90 02 09 eb 90 00 } //01 00 
		$a_03_2 = {31 df de f7 90 02 09 eb 90 00 } //01 00 
		$a_03_3 = {01 3a 66 0f 90 02 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}