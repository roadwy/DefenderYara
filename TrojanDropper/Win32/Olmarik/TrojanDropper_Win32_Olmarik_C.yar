
rule TrojanDropper_Win32_Olmarik_C{
	meta:
		description = "TrojanDropper:Win32/Olmarik.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 45 fc 3e 53 46 56 03 f1 8a 06 88 04 39 8b 45 fc 33 d2 b9 5f 32 00 00 f7 f1 89 45 fc 8a 45 08 88 06 eb } //1
		$a_01_1 = {8a 04 39 84 c0 74 09 3c 41 74 05 34 41 88 04 39 83 c1 08 3b ce 72 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}