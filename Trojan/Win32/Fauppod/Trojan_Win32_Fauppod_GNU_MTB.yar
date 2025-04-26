
rule Trojan_Win32_Fauppod_GNU_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 30 c8 c7 05 ?? ?? ?? ?? a8 06 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}