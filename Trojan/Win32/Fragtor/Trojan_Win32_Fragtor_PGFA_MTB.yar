
rule Trojan_Win32_Fragtor_PGFA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.PGFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f fe cd 66 0f 6e c1 0f 54 cc 66 0f 7e 1f 66 0f 67 c9 66 0f 67 c9 0f 57 c8 66 0f 7e 4f ?? 83 c7 ?? 81 fa ?? ?? ?? ?? 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}