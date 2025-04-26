
rule Trojan_Win32_Vidar_POV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.POV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f8 47 c1 e8 02 f7 e5 6b c2 e4 8d 14 19 0f b6 44 10 1f 32 44 19 ?? 88 44 1e 1f 43 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}