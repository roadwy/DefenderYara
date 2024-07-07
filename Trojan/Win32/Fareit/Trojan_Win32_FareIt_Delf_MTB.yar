
rule Trojan_Win32_FareIt_Delf_MTB{
	meta:
		description = "Trojan:Win32/FareIt.Delf!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 86 bc 00 00 00 8b 8e c0 00 00 00 69 c0 84 00 00 00 8b 95 dc fd ff ff 89 94 08 80 00 00 00 8b 86 bc 00 00 00 69 c0 84 00 00 00 03 86 c0 00 00 00 8d 8d f8 fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}