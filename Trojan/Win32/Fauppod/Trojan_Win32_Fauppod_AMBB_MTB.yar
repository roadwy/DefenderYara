
rule Trojan_Win32_Fauppod_AMBB_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 c7 05 90 01 08 30 c8 0f b6 c0 5d c3 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}