
rule Trojan_Win32_DllHijack_HNA_MTB{
	meta:
		description = "Trojan:Win32/DllHijack.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 95 20 ed ff ff fe 00 00 00 81 c2 3b 66 f3 56 69 85 20 ed ff ff fe 00 00 00 2b d0 81 f2 72 62 aa 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}