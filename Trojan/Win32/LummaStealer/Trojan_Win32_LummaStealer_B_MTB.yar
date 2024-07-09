
rule Trojan_Win32_LummaStealer_B_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 8b 04 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 } //2
		$a_01_1 = {57 69 6e 64 6f 77 73 20 31 30 } //1 Windows 10
		$a_01_2 = {57 69 6e 64 6f 77 73 20 31 31 } //1 Windows 11
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}