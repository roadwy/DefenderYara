
rule Trojan_Win32_Lazy_GXT_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 66 b9 a5 40 86 c9 66 f7 d1 66 89 45 04 f6 d5 9c 66 1b cf 12 ea 8f 44 25 00 } //10
		$a_01_1 = {64 33 2e 6c 61 72 67 65 73 64 65 72 2e 63 6f 6d } //1 d3.largesder.com
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}