
rule Trojan_Win32_Small_EM_MTB{
	meta:
		description = "Trojan:Win32/Small.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {83 c6 04 66 ba 31 df 39 fe 7c ef 66 bf ac e1 } //00 00 
	condition:
		any of ($a_*)
 
}