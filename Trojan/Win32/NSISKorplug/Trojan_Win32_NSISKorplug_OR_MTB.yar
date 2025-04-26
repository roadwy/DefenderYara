
rule Trojan_Win32_NSISKorplug_OR_MTB{
	meta:
		description = "Trojan:Win32/NSISKorplug.OR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 20 56 c6 44 24 21 69 c6 44 24 24 75 c6 44 24 25 61 c6 44 24 26 6c c6 44 24 27 50 c6 44 24 29 6f 88 54 24 2b c6 44 24 2c 63 c6 44 24 2e 00 } //1
		$a_01_1 = {c1 e8 08 c1 e9 10 88 46 07 88 4e 08 c1 ea 18 88 56 09 c6 46 0a c3 8b 4c 24 08 8d 44 24 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}