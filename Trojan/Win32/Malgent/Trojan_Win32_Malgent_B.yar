
rule Trojan_Win32_Malgent_B{
	meta:
		description = "Trojan:Win32/Malgent.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3d c4 36 4f 00 75 0c 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 40 3d f2 70 86 00 7c e5 ff 15 ?? ?? ?? ?? 33 c0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}