
rule Trojan_Win32_Ekstak_RD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 e8 97 65 fb ff e8 12 65 fb ff e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 10 53 56 57 e8 e2 e9 f5 ff 89 45 fc e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RD_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 68 34 2f 65 00 e8 c2 64 fb ff e8 8d 65 fb ff e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RD_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 2c ff 15 d8 94 65 00 85 c0 74 14 e8 cf 54 fb ff e8 7a 02 00 00 e8 f5 5b 09 00 e8 00 b5 12 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Ekstak_RD_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 b9 00 00 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 31 05 ?? ?? ?? ?? e8 ?? ?? 00 00 33 c0 50 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RD_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 14 56 50 ff 15 30 94 46 00 3d ?? ?? ?? ?? 74 14 8b 35 f0 97 46 00 6a 00 48 50 68 bb 00 00 00 ff 75 14 ff d6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RD_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 56 57 68 98 ?? 54 00 68 48 ?? 54 00 e8 cb ?? fa ff b9 41 00 00 00 33 c0 bf 50 ?? 54 00 f3 ab e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RD_MTB_8{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce 8b 7d 04 03 cf 8b e8 03 00 0c 3b cd 75 05 ?? ?? ?? ?? 2a 8b ?? ?? ?? ?? 00 0c 24 8b 7b 08 03 7b 0c 2c f9 89 7c 24 04 2b 00 89 73 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RD_MTB_9{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f1 a3 ?? ?? ?? 00 e8 ?? 00 00 00 6a 00 6a 00 e8 90 09 19 00 6a 32 e8 ?? ?? ?? 00 01 05 ?? ?? ?? 00 e8 ?? ?? ?? 00 8b c8 b8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RD_MTB_10{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 15 a4 80 65 00 e8 44 7b df ff e8 4f d7 da ff 68 ?? 03 00 00 e8 25 f6 ff ff 8b 15 e0 c4 65 00 03 d0 83 c4 04 89 15 e0 c4 65 00 e8 5f 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RD_MTB_11{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 32 33 c2 a3 ?? ?? ?? 00 e8 ?? ?? ?? 00 01 05 ?? ?? ?? 00 e8 ?? ?? ?? 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 ?? ?? ?? 00 e8 ?? ?? fe ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 52 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RD_MTB_12{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 56 57 68 ?? cf 65 00 e8 ?? 55 fb ff 8b f0 e9 } //4
		$a_01_1 = {40 00 00 40 5f 65 63 6f 72 65 5f } //1
		$a_01_2 = {40 00 00 40 2e 65 63 6f 72 65 } //1 @䀀攮潣敲
		$a_01_3 = {40 00 00 40 5f 64 63 6f 72 65 5f } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}