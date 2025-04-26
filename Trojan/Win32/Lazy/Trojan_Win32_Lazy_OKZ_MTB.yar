
rule Trojan_Win32_Lazy_OKZ_MTB{
	meta:
		description = "Trojan:Win32/Lazy.OKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 1c ff 50 10 8b 03 8b cb 6a 1c ff 50 18 8b 03 8b cb 6a 00 ff 50 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}