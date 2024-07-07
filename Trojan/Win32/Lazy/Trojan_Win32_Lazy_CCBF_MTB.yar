
rule Trojan_Win32_Lazy_CCBF_MTB{
	meta:
		description = "Trojan:Win32/Lazy.CCBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ac 32 02 aa 90 01 02 42 49 85 c9 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}