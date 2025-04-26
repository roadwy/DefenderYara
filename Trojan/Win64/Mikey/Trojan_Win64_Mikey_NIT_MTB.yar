
rule Trojan_Win64_Mikey_NIT_MTB{
	meta:
		description = "Trojan:Win64/Mikey.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 57 08 48 03 dd 44 8b 47 04 48 8b cb 48 03 d0 e8 ?? ?? 1a 00 89 5f fc 49 8b 06 ff c6 48 83 c7 28 0f b7 48 06 3b f1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}