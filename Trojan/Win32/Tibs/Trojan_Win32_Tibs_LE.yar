
rule Trojan_Win32_Tibs_LE{
	meta:
		description = "Trojan:Win32/Tibs.LE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {67 61 6e 64 c7 45 ?? 75 61 6c 50 c7 45 ?? 72 6f 74 65 c7 45 ?? 63 74 45 78 c6 45 ?? 00 c6 45 ?? 6b c6 45 ?? 00 c6 45 ?? 45 c6 45 ?? 00 c6 45 ?? 52 c6 45 ?? 00 c6 45 ?? 6e c6 45 ?? 00 c6 45 ?? 65 c6 45 ?? 00 c6 45 ?? 6c c6 45 ?? 00 c6 45 ?? 33 c6 45 ?? 00 c6 45 ?? 32 c6 45 ?? 00 c6 45 ?? 00 c6 45 ?? 00 ?? 8d 55 ?? c7 ?? 56 69 72 74 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}