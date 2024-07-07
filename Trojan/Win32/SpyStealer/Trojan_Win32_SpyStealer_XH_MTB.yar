
rule Trojan_Win32_SpyStealer_XH_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.XH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 1d a1 ed eb 01 d3 33 c0 79 90 01 02 4d 82 71 90 01 02 04 90 01 01 33 28 a2 90 01 04 ea 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}