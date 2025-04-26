
rule Trojan_Win32_Delf_OKM_MTB{
	meta:
		description = "Trojan:Win32/Delf.OKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 03 c6 40 99 89 45 f0 89 55 f4 eb ?? 46 4f 75 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}