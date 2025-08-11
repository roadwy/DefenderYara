
rule Trojan_Win32_Lazy_GPJ_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 ff 74 01 ea 31 3b 81 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}