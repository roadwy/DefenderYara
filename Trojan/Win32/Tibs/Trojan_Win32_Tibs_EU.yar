
rule Trojan_Win32_Tibs_EU{
	meta:
		description = "Trojan:Win32/Tibs.EU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 89 ce b9 00 00 00 00 81 c1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? [0-01] 8b 06 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}