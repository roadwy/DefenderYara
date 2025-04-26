
rule Trojan_Win32_Cridex_PVE_MTB{
	meta:
		description = "Trojan:Win32/Cridex.PVE!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d 92 27 01 00 8b 4d 08 89 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}