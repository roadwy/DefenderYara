
rule Trojan_Win32_LokiBot_DQ_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {54 6a 40 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 33 } //1
		$a_02_1 = {33 c0 8b f8 90 05 05 01 90 8a 8a ?? ?? ?? ?? 80 f1 5c 03 fe 88 0f 90 05 05 01 90 42 90 05 05 01 90 42 40 3d ?? ?? 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}