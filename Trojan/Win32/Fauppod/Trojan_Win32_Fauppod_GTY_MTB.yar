
rule Trojan_Win32_Fauppod_GTY_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 18 01 d0 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 28 89 c2 01 d0 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 38 b9 02 00 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}