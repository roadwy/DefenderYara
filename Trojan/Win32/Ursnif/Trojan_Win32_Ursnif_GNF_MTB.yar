
rule Trojan_Win32_Ursnif_GNF_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b ca 0f b6 85 90 01 04 03 c1 88 85 90 01 04 8b 8d 90 01 04 2b 8d 90 01 04 8b 55 90 01 01 8d 44 11 90 01 01 33 85 90 01 04 88 45 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}