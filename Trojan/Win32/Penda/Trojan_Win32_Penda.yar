
rule Trojan_Win32_Penda{
	meta:
		description = "Trojan:Win32/Penda,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e8 4b fc ff ff 83 c4 24 33 c0 bb ?? ?? 00 00 80 b0 ?? ?? 40 00 ?? 40 3b c3 72 f4 8b 3d ?? ?? 40 00 56 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}