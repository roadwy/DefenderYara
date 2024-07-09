
rule Trojan_Win32_Zenpak_RDQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c2 09 01 d0 40 83 c2 09 8d 05 ?? ?? ?? ?? 89 18 b8 06 00 00 00 83 f2 02 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}