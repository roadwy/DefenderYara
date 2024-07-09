
rule Trojan_Win32_RedLineStealer_K_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e2 c1 ea ?? 8b ca c1 e1 ?? 03 ca 8b 54 24 ?? 8b c2 2b c1 8a 80 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}