
rule Trojan_Win32_Tipikit_A{
	meta:
		description = "Trojan:Win32/Tipikit.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 0c 47 80 2e 7b 8a 06 88 87 ?? ?? 40 00 80 3d ?? ?? 43 00 0a 75 11 80 fb 14 75 0c 80 3e 1e 75 07 c6 05 22 76 43 00 01 b8 ?? ?? 40 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}