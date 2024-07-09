
rule Trojan_Win64_DarkLoader_A_MTB{
	meta:
		description = "Trojan:Win64/DarkLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c dc 60 48 8d 95 e0 ?? 00 00 4c 8b c7 ff 15 ?? ?? 00 00 85 c0 0f 88 ?? ?? ?? ?? 48 83 c7 06 48 ff c3 48 83 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}