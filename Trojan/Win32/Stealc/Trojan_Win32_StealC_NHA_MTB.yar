
rule Trojan_Win32_StealC_NHA_MTB{
	meta:
		description = "Trojan:Win32/StealC.NHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 8d 04 37 89 45 d8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 dc 8b 45 d8 31 45 fc 33 55 fc 89 55 d8 8b 45 d8 83 45 f8 64 29 45 f8 83 6d f8 64 83 3d f8 af a9 02 0c 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}