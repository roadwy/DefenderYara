
rule Trojan_Win32_Ekstak_RG_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e0 46 00 ff d0 68 30 10 47 00 68 d4 1a 47 00 ff 15 ?? e0 46 00 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 53 56 e8 c5 ff ff ff e9 } //1
		$a_03_1 = {40 00 00 40 2e ?? 64 65 78 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Ekstak_RG_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 53 56 57 e8 25 ff ff ff e8 60 ff ff ff 8b d8 b9 41 00 00 00 33 c0 bf 64 f7 4c 00 f3 ab e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RG_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 e9 a4 65 00 8b f0 e8 9b ff ff ff 8b 7d 14 83 c4 04 85 f6 74 0b 8d 55 fc 52 57 ff 15 50 43 65 00 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RG_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 e8 e7 ca f6 ff 68 38 b9 85 00 6a 00 ff 15 98 44 65 00 50 e8 d4 fe ff ff 31 05 78 ac 65 00 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RG_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {dc 05 58 e0 65 00 dd 1d 58 e0 65 00 ff 15 a4 b4 65 00 68 64 e0 65 00 ff 15 88 b4 65 00 50 ff 15 84 b4 65 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RG_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 8b 75 14 56 ff 15 ?? e4 46 00 ff 15 ?? e4 46 00 68 70 1c 47 00 ff 15 ?? ?? ?? ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RG_MTB_8{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 53 56 c7 45 f4 cc cc cc cc c7 45 f8 cc cc cc cc c7 45 fc cc cc cc cc e8 0c 64 fb ff 89 45 fc e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RG_MTB_9{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 33 c0 80 e2 3f 8a c2 0d c0 ff 00 00 83 c4 0c c3 90 90 90 90 55 8b ec 8b 45 14 50 e8 4a 98 20 00 e8 7f ff ff ff e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RG_MTB_10{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 00 40 65 00 68 44 70 65 00 6a 00 8d 4c 24 10 6a 01 51 c7 44 24 18 0c 00 00 00 89 74 24 1c c7 44 24 20 00 00 00 00 ff 15 a8 42 65 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RG_MTB_11{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 15 58 82 46 00 6a 00 ff 15 40 86 46 00 85 c0 7d 12 3d 06 01 01 80 75 11 68 00 b1 46 00 ff d3 85 c0 74 06 ff 15 44 86 46 00 e9 } //5
		$a_01_1 = {41 00 63 00 72 00 6f 00 42 00 72 00 6f 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 AcroBroker.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}