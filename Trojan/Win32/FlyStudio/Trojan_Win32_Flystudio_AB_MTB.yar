
rule Trojan_Win32_Flystudio_AB_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 46 2c 85 c0 74 0b 50 ff 15 88 25 4a 00 83 66 2c 00 83 7e 14 00 74 08 83 66 14 00 33 c0 } //2
		$a_03_1 = {83 ec 0c 50 ff 74 24 ?? 33 c0 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 8d 54 24 ?? 52 ff d3 8b 44 24 ?? 8b 54 24 ?? 8b 4c 24 ?? 83 c4 18 } //10
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*10) >=12
 
}