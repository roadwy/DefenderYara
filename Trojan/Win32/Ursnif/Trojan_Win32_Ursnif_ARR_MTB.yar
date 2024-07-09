
rule Trojan_Win32_Ursnif_ARR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {40 0f af c3 ff 4c 24 ?? 0f b7 c0 0f b7 d8 8d b4 19 ?? ?? ?? ?? 0f 85 90 0a 48 00 8b 44 24 ?? 8b 4c 24 ?? 83 44 24 ?? ?? 81 c5 b4 9d d8 01 89 28 8b 44 24 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}