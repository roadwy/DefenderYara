
rule Trojan_Win32_DarkGate_BAY_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.BAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ce f7 e7 8b c7 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 13 2b c8 03 cf 8a 44 0c 24 32 87 3c 21 6e 00 88 04 2f 47 81 ff 00 06 33 00 72 cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}