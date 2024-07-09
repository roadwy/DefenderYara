
rule Trojan_Win32_Aptdrop_R{
	meta:
		description = "Trojan:Win32/Aptdrop.R,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b cf 8b c7 c1 e9 05 03 4c 24 ?? c1 e0 04 03 44 24 ?? 33 c8 8d 04 2f 33 c8 8b 44 24 ?? 2b d9 6a f7 59 2b c8 03 e9 4e 75 ?? 8b 74 24 24 89 7e 04 5f 89 1e 5e 5d 5b 83 c4 ?? c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}