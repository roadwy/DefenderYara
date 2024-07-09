
rule Trojan_Win32_Remcos_RO_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 04 0a 34 ?? 04 ?? 34 ?? 2c ?? 88 01 41 83 ee 01 75 ?? 68 de c0 ad de } //1
		$a_02_1 = {8a 04 0a 34 ?? 2c ?? 34 ?? 2c ?? 88 01 41 83 ee 01 75 ?? 68 de c0 ad de } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Remcos_RO_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {85 db 66 81 fb ee 00 ff 37 83 ff ?? 66 83 fa ?? 66 81 fa ?? ?? 66 83 fb ?? 85 d2 81 fb ?? ?? ?? ?? 5f 66 81 fb ?? ?? 66 a9 ?? ?? 81 ff ?? ?? ?? ?? 66 3d ?? ?? 66 85 d2 83 f8 ?? 66 85 d2 66 83 ff ?? 31 f7 66 83 fa ?? 66 85 d2 81 fa ?? ?? ?? ?? 83 ff ?? 66 83 f8 ?? 85 c0 89 3c 10 85 c0 85 db } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}