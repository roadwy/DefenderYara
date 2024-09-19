
rule Trojan_Win32_Ekstak_RB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 68 90 40 65 00 e8 12 65 fb ff e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 53 56 57 e8 c2 ee f5 ff 89 45 fc e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 57 e8 84 ff ff ff b9 41 00 00 00 33 c0 bf 30 e6 4c 00 f3 ab } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RB_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 68 54 4f 65 00 e8 92 63 fb ff 8b 45 08 83 c4 04 68 54 4f 65 00 50 e8 b1 64 fb ff e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RB_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 10 53 56 57 8b 45 08 50 e8 ?? e8 f5 ff 83 c4 04 25 ff ff 00 00 89 45 fc e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RB_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 08 56 57 ff 15 d8 c1 4b 00 68 ?? e0 4b 00 6a 01 6a 00 8b f8 ff 15 dc c1 4b 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RB_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f0 11 f7 d8 1b c0 40 83 c4 ?? c3 33 c0 5f 83 c4 } //1
		$a_01_1 = {55 8b ec 51 56 e8 f6 69 fb ff e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Ekstak_RB_MTB_8{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 08 a3 e0 ca 65 00 ff 15 54 95 65 00 a1 e0 ca 65 00 85 c0 74 13 68 a8 bb 45 01 56 ff 15 58 90 65 00 56 ff 15 54 90 65 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RB_MTB_9{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 ec 04 01 00 00 56 57 b9 41 00 00 00 33 c0 8d bd fc fe ff ff f3 ab 8b 45 10 8d 8d fc fe ff ff 50 51 ff 15 60 40 4b 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RB_MTB_10{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 6a 00 ff 15 50 67 65 00 56 e8 18 a1 20 00 e9 } //5
		$a_01_1 = {53 00 68 00 72 00 65 00 64 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 Shredder.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Ekstak_RB_MTB_11{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 ff 15 70 f0 46 00 8b 75 14 68 50 1c 27 01 56 ff 15 58 f0 46 00 e9 } //5
		$a_01_1 = {53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 ShutdownScheduler.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Ekstak_RB_MTB_12{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 14 50 ff 15 94 f0 46 00 ff 15 ?? f0 46 00 3d ?? ?? ?? ?? 75 05 e8 21 b1 01 00 e9 } //5
		$a_01_1 = {53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 ShutdownScheduler.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}