
rule Trojan_Win32_Nebuler_Q{
	meta:
		description = "Trojan:Win32/Nebuler.Q,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 42 01 8b 8d ?? ?? ?? ?? 0f be 91 ?? ?? ?? ?? 33 c2 8b 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01 90 09 09 00 8b 55 08 03 95 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}