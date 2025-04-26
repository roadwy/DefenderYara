
rule Trojan_Win32_Adload_MR_MTB{
	meta:
		description = "Trojan:Win32/Adload.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f1 8b 45 ?? 0f be 0c 10 8b 55 ?? 0f b6 44 15 ?? 33 c1 8b 4d ?? 88 44 0d ?? eb 90 09 05 00 b9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}