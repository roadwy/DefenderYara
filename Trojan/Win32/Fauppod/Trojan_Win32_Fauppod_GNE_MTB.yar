
rule Trojan_Win32_Fauppod_GNE_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 38 42 29 c2 31 d0 8d 05 ?? ?? ?? ?? 89 28 31 d0 89 35 ?? ?? ?? ?? 83 f2 ?? 4a 48 31 1d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}