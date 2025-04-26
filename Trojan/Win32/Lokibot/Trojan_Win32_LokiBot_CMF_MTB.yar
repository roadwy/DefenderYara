
rule Trojan_Win32_LokiBot_CMF_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.CMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 6a 0c 99 5e f7 fe 8a 82 ?? ?? ?? ?? 30 04 0f 41 3b cb 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}