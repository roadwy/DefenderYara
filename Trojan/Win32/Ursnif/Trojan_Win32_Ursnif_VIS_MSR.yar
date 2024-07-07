
rule Trojan_Win32_Ursnif_VIS_MSR{
	meta:
		description = "Trojan:Win32/Ursnif.VIS!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 8c 10 c0 b2 07 00 89 0d 90 01 04 8b 15 90 01 04 81 ea be ac 00 00 89 15 90 01 04 a1 90 01 04 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}