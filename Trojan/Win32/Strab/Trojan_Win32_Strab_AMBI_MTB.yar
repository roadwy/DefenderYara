
rule Trojan_Win32_Strab_AMBI_MTB{
	meta:
		description = "Trojan:Win32/Strab.AMBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 c8 0f b6 4d 90 01 01 31 c8 88 c1 8b 45 90 01 01 88 0c 05 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Strab_AMBI_MTB_2{
	meta:
		description = "Trojan:Win32/Strab.AMBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 fe 0f b6 81 90 01 04 c0 c8 03 32 82 90 01 04 88 81 90 01 04 8d 42 01 99 f7 fe 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}