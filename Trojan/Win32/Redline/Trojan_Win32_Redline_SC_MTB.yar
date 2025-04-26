
rule Trojan_Win32_Redline_SC_MTB{
	meta:
		description = "Trojan:Win32/Redline.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {e0 7f 56 00 c7 05 ?? ?? ?? ?? dc 7f 56 00 c7 05 ?? ?? ?? ?? d8 7f 56 00 c7 05 ?? ?? ?? ?? 6c 00 00 00 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}