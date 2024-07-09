
rule Trojan_Win32_AveMaria_AG_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 e6 8b c6 c1 ea ?? 8d 0c 92 c1 e1 ?? 2b c1 8a 44 05 ?? 30 86 ?? ?? ?? ?? 46 81 fe } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}