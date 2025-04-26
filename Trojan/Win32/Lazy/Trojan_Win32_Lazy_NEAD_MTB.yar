
rule Trojan_Win32_Lazy_NEAD_MTB{
	meta:
		description = "Trojan:Win32/Lazy.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e6 c1 ea 04 8d 04 52 c1 e0 03 2b c8 8a 04 31 30 04 37 46 3b f3 72 d0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}