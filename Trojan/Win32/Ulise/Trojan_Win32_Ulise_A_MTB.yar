
rule Trojan_Win32_Ulise_A_MTB{
	meta:
		description = "Trojan:Win32/Ulise.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f0 8d 85 d8 fe ff ff 50 56 c7 85 d8 fe ff ff 28 01 00 00 e8 ?? ?? 00 00 85 c0 74 ?? 39 bd e0 fe ff ff 74 ?? 8d 85 d8 fe ff ff 50 56 e8 } //2
		$a_03_1 = {80 74 05 e8 ?? 40 83 f8 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}