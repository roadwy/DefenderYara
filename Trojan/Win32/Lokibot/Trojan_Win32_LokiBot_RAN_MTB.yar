
rule Trojan_Win32_LokiBot_RAN_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 d0 d6 1c 00 3b f0 7f 1f ff 15 ?? ?? ?? ?? 6a 00 6a 00 e8 ?? ?? ?? ?? ff d3 8b c7 03 c6 0f 80 f4 00 00 00 8b f0 eb d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}