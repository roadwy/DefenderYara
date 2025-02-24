
rule Trojan_Win32_Ursnif_OKA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.OKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 53 68 04 22 41 00 ff 15 ?? ?? ?? ?? eb ?? 33 db 83 ee 01 78 0d e8 a6 ed ff ff 30 04 37 83 ee 01 79 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}