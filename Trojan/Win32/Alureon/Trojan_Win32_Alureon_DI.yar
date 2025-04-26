
rule Trojan_Win32_Alureon_DI{
	meta:
		description = "Trojan:Win32/Alureon.DI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 74 24 04 ?? d8 ?? 90 90 ?? 6a 30 ?? d8 ?? 90 90 ?? 58 e9 ?? ?? 00 00 ?? ?? ?? e9 ?? ?? 00 00 83 ec 04 97 d8 ?? 90 90 97 33 c9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}