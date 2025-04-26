
rule Trojan_Win32_Alureon_EA{
	meta:
		description = "Trojan:Win32/Alureon.EA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d0 53 53 53 8b ?? ?? ?? ?? 40 00 ff d0 68 33 2b 38 6a e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ff d0 83 f8 05 0f 84 ?? 00 00 00 83 f8 02 0f 85 ?? 00 00 00 80 7c 24 ?? 61 0f 84 ?? 00 00 00 33 c0 e9 ?? ?? 00 00 6a 40 68 00 30 00 00 68 00 38 0b 00 53 8b [0-04] 40 00 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}