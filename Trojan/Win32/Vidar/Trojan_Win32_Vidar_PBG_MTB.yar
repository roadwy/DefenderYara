
rule Trojan_Win32_Vidar_PBG_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 80 8b 15 ?? ?? ?? ?? 8b 44 c2 10 a3 30 ec 45 00 a1 2c ec 45 00 3b 05 30 ec 45 00 73 ?? a1 30 ec 45 00 31 05 2c ec 45 00 a1 2c ec 45 00 31 05 30 ec 45 00 a1 30 ec 45 00 31 05 2c ec 45 00 6a 04 68 00 10 00 00 a1 2c ec 45 00 50 8b 07 8d 04 80 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}