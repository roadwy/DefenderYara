
rule Trojan_Win32_DarkGate_NEQ_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.NEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 33 c0 8b ce 2a c8 32 0c 07 8b 5d fc 8b 1b 88 0c 03 40 4a 75 ed } //5
		$a_03_1 = {8b 55 f4 8a 14 32 8b 4d f8 32 14 19 88 14 30 8b 45 f8 e8 ?? ?? ?? ?? 50 8b 45 f8 0f b6 04 18 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*3) >=8
 
}