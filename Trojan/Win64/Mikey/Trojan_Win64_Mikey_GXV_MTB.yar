
rule Trojan_Win64_Mikey_GXV_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 02 16 c2 8e 00 de 1b 93 ?? ?? ?? ?? 30 0f 0b 17 f4 ?? ?? 06 24 e6 bc ?? ?? ?? ?? 09 07 c0 23 d1 fe 83 } //5
		$a_03_1 = {cc 31 62 09 4a 63 22 28 9e ?? ?? ?? ?? 49 ec } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}