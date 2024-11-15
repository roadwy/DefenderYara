
rule Trojan_Win32_Vidar_MOZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 50 e8 17 ?? ?? ?? 33 c0 59 59 89 44 24 10 89 44 24 ?? 89 44 24 18 8b 7c 24 1c 8b 4c 24 20 8a 44 0c 3c 8b 4c 24 38 30 04 29 45 3b 6b 04 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}