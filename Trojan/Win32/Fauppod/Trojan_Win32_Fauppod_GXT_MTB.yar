
rule Trojan_Win32_Fauppod_GXT_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 01 d0 4a 42 01 25 90 01 04 01 d0 83 c2 90 01 01 48 90 01 02 4a 8d 05 90 01 04 89 18 83 c0 90 01 01 01 3d 90 01 04 83 f2 90 01 01 89 d0 8d 05 90 01 04 31 28 31 35 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}