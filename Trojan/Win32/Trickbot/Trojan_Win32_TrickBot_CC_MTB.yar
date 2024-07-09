
rule Trojan_Win32_TrickBot_CC_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {32 da 88 1c 07 8b 84 24 ?? ?? ?? ?? 47 3b f8 0f 8c ?? ?? ?? ?? 5b 5f 5e 5d 81 c4 44 03 00 00 c3 } //1
		$a_02_1 = {6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 8a 4c 24 ?? 8b 84 24 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}