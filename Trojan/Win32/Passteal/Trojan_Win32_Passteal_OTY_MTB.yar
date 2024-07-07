
rule Trojan_Win32_Passteal_OTY_MTB{
	meta:
		description = "Trojan:Win32/Passteal.OTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 f1 10 c6 85 5e ff ff ff 01 c1 f9 03 89 8d ac fd ff ff c6 45 a8 01 89 4d ac } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}