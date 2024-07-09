
rule Trojan_Win32_PikaBot_LKC_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.LKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 44 0d b0 34 ?? 88 84 0d ?? ?? ff ff 41 83 f9 0c 7c ed } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}