
rule Trojan_Win32_Phorpiex_RB_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 ff 7f 00 00 f7 f9 81 c2 e8 03 00 00 52 e8 ?? ?? ?? ?? 99 b9 ff 7f 00 00 f7 f9 [0-10] 81 c2 e8 03 00 00 52 8d [0-06] 52 68 [0-10] 50 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Phorpiex_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Phorpiex.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 30 75 00 00 f7 f9 81 c2 10 27 00 00 52 e8 ?? ?? ?? ?? 99 b9 30 75 00 00 f7 f9 81 c2 10 27 00 00 52 8d ?? ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}