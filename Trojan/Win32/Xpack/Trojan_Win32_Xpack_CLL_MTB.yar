
rule Trojan_Win32_Xpack_CLL_MTB{
	meta:
		description = "Trojan:Win32/Xpack.CLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 06 83 c6 01 68 90 01 04 83 c4 90 01 01 89 c0 32 02 89 c0 47 88 47 ff 68 90 01 04 83 c4 90 01 01 42 83 e9 90 01 01 83 ec 90 01 01 c7 04 24 90 01 04 83 c4 90 01 01 83 ec 90 01 01 c7 04 24 90 01 04 83 c4 90 01 01 85 c9 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}