
rule Trojan_Win32_Gandcrab_AD_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 44 19 01 0f b6 14 19 88 54 24 ?? 88 44 24 ?? 8a 44 19 ?? 8a d0 c0 e2 ?? 0a 54 19 ?? 8d 74 24 ?? 8d 7c 24 ?? 88 54 24 ?? e8 } //1
		$a_02_1 = {0f b6 4c 24 ?? 8b 44 24 ?? 0f b6 54 24 ?? 88 0c 28 0f b6 4c 24 ?? 45 88 14 28 8b 54 24 ?? 45 88 0c 28 83 c3 04 45 3b 1a 72 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}