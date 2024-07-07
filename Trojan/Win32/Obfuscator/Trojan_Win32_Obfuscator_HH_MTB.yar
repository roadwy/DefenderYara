
rule Trojan_Win32_Obfuscator_HH_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.HH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 d0 83 e2 1f 0f b6 92 90 01 04 32 14 03 8b 5c 24 28 88 50 04 8b 54 24 24 03 d0 83 e2 1f 0f b6 92 90 01 04 32 14 03 83 c0 06 88 50 ff 81 f9 90 01 04 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}