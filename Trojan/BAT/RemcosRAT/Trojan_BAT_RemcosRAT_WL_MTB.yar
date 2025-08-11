
rule Trojan_BAT_RemcosRAT_WL_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.WL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 08 07 61 11 08 61 13 09 08 11 07 11 09 } //1 ࠓ愇ࠑ፡ࠉܑऑ
	condition:
		((#a_01_0  & 1)*1) >=1
 
}