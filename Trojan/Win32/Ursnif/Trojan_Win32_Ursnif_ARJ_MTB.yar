
rule Trojan_Win32_Ursnif_ARJ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 0c 81 c6 90 01 04 89 35 90 01 04 89 31 8d 0c 50 8b 15 90 01 04 03 cb 8d 0c 4d 90 01 04 0f b7 d9 8d 0c 3a 81 f9 90 01 04 74 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}