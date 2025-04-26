
rule Trojan_Win32_Strab_RF_MTB{
	meta:
		description = "Trojan:Win32/Strab.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f2 4e 88 95 37 ff ff ff 0f b7 05 ?? ?? ?? ?? 99 05 5b 0f d8 99 81 d2 54 73 0e 00 a3 ?? ?? ?? ?? 8b 45 c0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Strab_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Strab.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 8b 45 fc 33 d0 89 55 fc 8b 55 fc 8b f3 85 d2 74 03 8b 75 fc 8b 45 fc 99 f7 fe 8b 55 fc bf 05 00 00 00 0f af c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}