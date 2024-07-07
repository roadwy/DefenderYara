
rule Trojan_Win32_Ursnif_DSK_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 7c fd bc 01 81 7c 24 24 69 77 01 00 8b 54 24 18 89 44 24 14 a3 90 01 04 89 02 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}