
rule Trojan_Win32_Fareit_RQ_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {32 c2 88 01 c3 8d 40 00 55 8b ec 51 89 45 ?? 8b 7d ?? 81 c7 ?? ?? ?? ?? ff d7 59 5d c3 8d 40 00 55 8b ec 51 53 56 57 6a ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}