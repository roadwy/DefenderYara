
rule Trojan_Win32_LokiBot_GM_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 06 88 45 [0-40] 8a 84 85 ?? ?? ?? ?? 32 45 ?? 8b 55 ?? 88 02 [0-30] ff 4d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}