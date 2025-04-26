
rule Trojan_Win32_ICLoader_GTN_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ba ee ?? ?? ?? 6b 70 00 00 ?? 0a 00 6d f5 94 e2 2d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}