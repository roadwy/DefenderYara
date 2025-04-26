
rule Trojan_Win32_Qhost_CC{
	meta:
		description = "Trojan:Win32/Qhost.CC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a d0 80 c2 0e 30 94 0d ?? ?? ?? ?? 83 f8 03 7e 04 33 c0 eb 03 83 c0 01 83 c1 01 81 f9 ?? ?? ?? ?? 7c dd } //1
		$a_00_1 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 31 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}