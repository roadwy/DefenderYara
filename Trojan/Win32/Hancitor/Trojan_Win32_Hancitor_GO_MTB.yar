
rule Trojan_Win32_Hancitor_GO_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b cb 2b ce 83 c2 90 01 01 0f af f3 03 d1 69 de 90 01 04 8b 4c 24 90 01 01 8d 72 90 01 01 8b 54 24 90 01 01 81 c1 90 01 04 03 f0 89 0d 90 01 04 c7 05 90 01 04 00 00 00 00 89 0a 8b d7 8b 4c 24 90 01 01 2b d6 83 c1 04 83 ea 90 01 01 83 6c 24 90 01 01 01 89 4c 24 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}