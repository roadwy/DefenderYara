
rule Trojan_Win32_Ursnif_VIS_MSR{
	meta:
		description = "Trojan:Win32/Ursnif.VIS!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 8c 10 c0 b2 07 00 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea be ac 00 00 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}