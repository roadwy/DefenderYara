
rule Trojan_Win32_Downexec_A{
	meta:
		description = "Trojan:Win32/Downexec.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 ff 01 00 00 85 c0 76 15 6a 00 8b 45 ?? 50 e8 ?? ?? ?? ff c1 e8 09 40 c1 e0 09 89 43 ?? c7 43 ?? e0 00 00 e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}