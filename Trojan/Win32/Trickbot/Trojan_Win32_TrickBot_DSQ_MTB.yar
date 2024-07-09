
rule Trojan_Win32_TrickBot_DSQ_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f0 33 d2 b9 ?? 00 00 00 f7 f1 8b 45 f8 0f be 0c 10 8b 55 f0 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f0 88 81 ?? ?? ?? ?? 8b 55 f0 83 c2 01 89 55 f0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}