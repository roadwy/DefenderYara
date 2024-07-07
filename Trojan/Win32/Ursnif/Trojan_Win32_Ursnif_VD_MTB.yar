
rule Trojan_Win32_Ursnif_VD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ff c7 05 90 01 08 01 05 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 90 09 24 00 a1 90 01 04 a3 90 01 04 a1 90 01 04 a3 90 01 04 a3 90 01 04 31 0d 90 01 04 a1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}