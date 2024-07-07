
rule Trojan_Win32_Raccoon_DEM_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.DEM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 8b 44 24 04 8b 4c 24 08 31 08 c2 08 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}