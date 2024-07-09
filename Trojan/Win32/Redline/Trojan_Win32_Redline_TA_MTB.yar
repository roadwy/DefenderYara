
rule Trojan_Win32_Redline_TA_MTB{
	meta:
		description = "Trojan:Win32/Redline.TA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c8 31 d2 f7 b4 ?? ?? ?? ?? 00 89 e8 c1 ea 02 f6 24 17 30 04 0b 83 c1 01 39 f1 75 e3 83 c4 7c 5b 5e 5f 5d c3 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}