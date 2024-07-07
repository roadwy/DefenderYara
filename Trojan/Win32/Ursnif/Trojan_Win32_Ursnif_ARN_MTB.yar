
rule Trojan_Win32_Ursnif_ARN_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 d8 13 fa 89 7c 24 90 01 01 8b 7c 24 90 01 01 8b 15 90 01 04 69 c3 90 01 04 01 44 24 90 01 01 0f b7 c7 03 44 24 90 01 01 3d 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}