
rule Trojan_Win32_LokiBot_EU_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 01 66 8b 00 f6 c4 f9 74 ?? 8b 1d ?? ?? ?? ?? 8b 1b 03 1d ?? ?? ?? ?? 66 25 ff 0f 0f b7 c0 03 d8 a1 ?? ?? ?? ?? 01 03 83 01 02 4a 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}