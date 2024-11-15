
rule Trojan_Win64_WarmCookie_MKV_MTB{
	meta:
		description = "Trojan:Win64/WarmCookie.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 48 f7 f7 4d 8d 49 01 0f b6 04 32 41 02 c0 02 d8 0f b6 cb 42 0f b6 44 11 ?? 41 88 41 ff 4b 8d 04 0b 46 88 44 11 ?? 48 3d 00 01 00 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}