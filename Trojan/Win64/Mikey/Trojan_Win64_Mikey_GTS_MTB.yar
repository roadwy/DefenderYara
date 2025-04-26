
rule Trojan_Win64_Mikey_GTS_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 6b 94 c2 ?? ?? ?? ?? 21 89 e7 30 a7 ?? ?? ?? ?? 12 d0 5a f7 0c 31 ?? ?? ?? ?? 30 2c 41 3a 42 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}