
rule Trojan_Win32_RedLineStealer_M_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 17 80 37 ?? 47 e2 f8 5f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}