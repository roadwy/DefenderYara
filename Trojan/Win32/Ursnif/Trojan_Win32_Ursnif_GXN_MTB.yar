
rule Trojan_Win32_Ursnif_GXN_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 14 41 0f be 85 90 01 04 0f af 85 90 01 04 0f be 8d 90 01 04 8b b5 90 01 04 2b f1 33 c6 03 d0 a1 90 01 04 03 85 90 01 04 88 10 0f b6 4d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}