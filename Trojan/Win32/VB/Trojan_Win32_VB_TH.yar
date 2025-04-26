
rule Trojan_Win32_VB_TH{
	meta:
		description = "Trojan:Win32/VB.TH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe a0 46 00 00 00 00 00 00 10 3a 54 ff 02 00 25 08 64 ff 2c 0a 00 00 00 00 13 fe c1 54 ff 9a 02 00 00 25 08 64 ff 2c 01 00 00 00 00 0d 08 64 ff fe a0 40 00 00 00 00 00 } //1
		$a_00_1 = {6a 00 75 00 73 00 74 00 34 00 79 00 6f 00 75 00 72 00 6e 00 61 00 6d 00 65 00 2e 00 62 00 6f 00 75 00 6e 00 63 00 65 00 6d 00 65 00 2e 00 6e 00 65 00 74 00 } //1 just4yourname.bounceme.net
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}