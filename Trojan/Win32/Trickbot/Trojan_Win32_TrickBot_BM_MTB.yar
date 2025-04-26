
rule Trojan_Win32_TrickBot_BM_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 18 88 11 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 02 5d 10 8b 45 08 8b 4d fc 83 c4 0c 0f b6 d3 03 c1 8a 94 15 f0 fe ff ff 30 10 41 3b 4d 0c 89 4d fc 7c } //1
		$a_02_1 = {f7 f1 8a 04 3e 8a 14 ?? 32 c2 88 04 3e 46 3b f5 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}