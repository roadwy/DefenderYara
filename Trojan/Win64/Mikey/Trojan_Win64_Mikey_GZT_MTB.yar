
rule Trojan_Win64_Mikey_GZT_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {5b 59 8b d1 32 fd 24 } //5
		$a_03_1 = {14 1c 34 39 10 b0 ?? ?? ?? ?? 31 74 9a ?? 59 ?? ?? ?? ?? 54 5e f6 ed } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}