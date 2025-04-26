
rule Trojan_Win32_Copak_GJL_MTB{
	meta:
		description = "Trojan:Win32/Copak.GJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 5a 01 f8 e8 ?? ?? ?? ?? 01 ff bf ?? ?? ?? ?? 31 11 41 21 ff 83 ec 04 89 3c 24 5f 39 f1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}