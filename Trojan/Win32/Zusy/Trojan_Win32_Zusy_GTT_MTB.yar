
rule Trojan_Win32_Zusy_GTT_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {57 3f 03 6e ?? 5b 91 8c 4f ?? 4f 3c ?? 24 ?? 14 ?? 4a 31 de } //5
		$a_03_1 = {ec 5f 94 2f 84 56 ?? 09 3e cc 8b 44 ba c7 } //5
		$a_01_2 = {5c 4b 73 5c 42 4c 41 43 4b 5c } //1 \Ks\BLACK\
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}