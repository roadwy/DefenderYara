
rule Trojan_Win32_Ursnif_ARN_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 d8 13 fa 89 7c 24 ?? 8b 7c 24 ?? 8b 15 ?? ?? ?? ?? 69 c3 ?? ?? ?? ?? 01 44 24 ?? 0f b7 c7 03 44 24 ?? 3d ?? ?? ?? ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}