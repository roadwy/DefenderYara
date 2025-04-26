
rule Trojan_Win32_Fauppod_GNV_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 45 ff 88 4d fe 8a 45 ff 8a 4d fe 30 c8 a2 60 7f 5b 00 c7 05 ?? ?? ?? ?? a8 06 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}