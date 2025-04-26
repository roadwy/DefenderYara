
rule Trojan_Win32_Fauppod_PM_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 ?? 90 90 90 90 46 8a 46 ?? 51 83 c4 04 53 83 c4 04 32 02 88 07 83 c7 01 90 90 42 83 e9 01 85 c9 75 ?? 61 c9 c2 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}