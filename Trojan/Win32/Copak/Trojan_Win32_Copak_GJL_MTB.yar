
rule Trojan_Win32_Copak_GJL_MTB{
	meta:
		description = "Trojan:Win32/Copak.GJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 90 01 04 5a 01 f8 e8 90 01 04 01 ff bf 90 01 04 31 11 41 21 ff 83 ec 04 89 3c 24 5f 39 f1 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}