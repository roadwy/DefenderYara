
rule Trojan_Win32_DarkGate_C_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 c2 f6 d0 5a 88 02 ff 06 4b } //2
		$a_03_1 = {8b 06 0f b6 44 05 ?? 31 05 ?? ?? ?? ?? ff 06 4b } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}