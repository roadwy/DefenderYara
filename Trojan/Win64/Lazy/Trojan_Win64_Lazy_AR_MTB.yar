
rule Trojan_Win64_Lazy_AR_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 59 52 33 41 58 4c 55 79 30 42 58 33 30 4f 51 4e 66 67 53 75 6b 6c 6a 56 35 } //1 jYR3AXLUy0BX30OQNfgSukljV5
	condition:
		((#a_01_0  & 1)*1) >=1
 
}