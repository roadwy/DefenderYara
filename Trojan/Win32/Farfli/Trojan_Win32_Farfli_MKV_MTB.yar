
rule Trojan_Win32_Farfli_MKV_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b f7 89 55 e4 8b 43 14 8d 0c 3e 83 e1 03 8a 04 01 30 07 47 4a 75 ee } //5
		$a_01_1 = {8b 4d 0c 8b c6 83 e0 03 8a 04 08 30 04 1e 46 3b f2 7c f0 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}