
rule Trojan_Win32_Lazy_GPAK_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GPAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 01 ea 31 ?? ?? ?? 81 c6 04 00 00 00 39 ce 75 ed } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}