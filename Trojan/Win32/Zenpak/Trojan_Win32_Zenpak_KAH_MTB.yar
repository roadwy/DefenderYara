
rule Trojan_Win32_Zenpak_KAH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b c1 0f b6 55 90 01 01 33 c2 8b 4d 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}