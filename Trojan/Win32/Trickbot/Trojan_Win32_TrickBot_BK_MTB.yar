
rule Trojan_Win32_TrickBot_BK_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 b9 40 34 01 00 f7 f9 8b 45 ?? 33 c9 8a 0c 10 89 4d ?? 8b 55 ?? 03 55 ?? 0f be 02 50 8b 4d ?? 51 e8 ?? ?? ?? ?? 83 c4 08 8b 55 ?? 03 55 ?? 88 02 e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}