
rule Trojan_Win32_RedLineStealer_UE_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.UE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 03 55 90 01 01 0f b6 02 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 e9 90 01 04 8b e5 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}