
rule Trojan_Win32_Copak_GJT_MTB{
	meta:
		description = "Trojan:Win32/Copak.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 13 01 f8 21 ff 43 4f 81 c7 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? 39 f3 75 ?? 21 f8 c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Copak_GJT_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 59 81 c1 ?? ?? ?? ?? 31 1f 47 81 c1 ?? ?? ?? ?? 39 d7 75 ?? c3 81 c6 ?? ?? ?? ?? 8d 1c 03 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Copak_GJT_MTB_3{
	meta:
		description = "Trojan:Win32/Copak.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 34 24 83 c4 ?? e8 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 83 ec ?? 89 14 24 5a 31 37 21 da 47 81 ea ?? ?? ?? ?? 29 db 39 cf } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}