
rule Trojan_Win32_Redline_IF_MTB{
	meta:
		description = "Trojan:Win32/Redline.IF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 5c 24 18 33 f6 39 74 24 20 76 17 ff d7 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 04 1e 46 3b 74 24 20 72 e9 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}