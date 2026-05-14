
rule Trojan_Win32_SDum_BMD_MTB{
	meta:
		description = "Trojan:Win32/SDum.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b c8 41 83 e1 ?? 47 0f b6 0c 01 44 30 0c 01 48 ff c0 48 3b c2 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}