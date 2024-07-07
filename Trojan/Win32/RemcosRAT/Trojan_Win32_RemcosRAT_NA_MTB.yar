
rule Trojan_Win32_RemcosRAT_NA_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 a5 d5 01 00 83 c4 90 01 01 3d 90 01 04 0f 83 90 01 04 89 c1 83 f8 90 01 01 77 07 88 4e 90 01 01 89 f7 eb 26 89 cb 83 cb 0f 43 53 89 cf e8 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}