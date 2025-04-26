
rule Trojan_Win32_Tibs_EV{
	meta:
		description = "Trojan:Win32/Tibs.EV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 89 ce c1 e9 ?? [0-09] 81 c1 ?? ?? ?? ?? 81 (c1|e9) ?? ?? ?? ?? [0-03] 8b 06 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}