
rule Trojan_Win32_CryptBot_CC_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 f7 75 08 8a 0c 1a 30 0c 3e 46 81 fe ?? ?? ?? ?? 72 } //5
		$a_03_1 = {0f af d1 8b 4d 08 8b c1 56 8b 35 ?? ?? ?? ?? c1 e8 ?? 88 44 96 01 8b c1 88 0c 96 c1 e8 ?? c1 e9 ?? 88 44 96 03 88 4c 96 02 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}