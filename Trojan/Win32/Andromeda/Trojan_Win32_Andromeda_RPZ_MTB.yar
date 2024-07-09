
rule Trojan_Win32_Andromeda_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Andromeda.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 8b 51 54 52 8b 45 08 8b 48 0c 51 8b 55 d0 52 8b 45 d8 50 8b 4d 08 8b 91 80 00 00 00 ff d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Andromeda_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Andromeda.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 10 00 00 8b 45 08 8b 40 04 ff 70 09 6a 00 8b 45 08 ff 50 24 89 45 f8 83 65 f4 00 6a 00 8d 45 f4 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Andromeda_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Andromeda.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 14 56 57 8b 7d 08 33 f6 89 47 0c 39 75 10 76 15 8b 45 0c 57 8d 14 06 e8 ?? ?? ?? ?? 30 02 46 59 3b 75 10 72 eb 5f 5e 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}