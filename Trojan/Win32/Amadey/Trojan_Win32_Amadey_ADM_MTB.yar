
rule Trojan_Win32_Amadey_ADM_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 fa 03 0f b6 45 ?? c1 e0 05 0b d0 88 55 ?? 0f b6 4d ?? f7 d9 88 4d ?? 0f b6 55 ?? f7 d2 88 55 ?? 0f b6 45 ?? c1 f8 06 0f b6 4d ?? c1 e1 02 0b c1 88 45 ?? 0f b6 55 ?? 2b 55 ?? 88 55 ?? 8b ?? bc 8a 4d ee 88 4c 05 94 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}