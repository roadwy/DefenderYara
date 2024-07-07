
rule Trojan_Win32_Ursnif_I_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 33 89 7c 24 90 01 01 81 6c 24 90 02 30 81 44 24 90 02 30 81 6c 24 90 02 30 81 44 24 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}