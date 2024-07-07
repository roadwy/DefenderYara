
rule Trojan_Win32_DelfInject_RT_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 8b 08 f6 c5 f0 74 90 01 01 8b 45 90 01 01 8b 00 03 05 90 01 04 66 81 e1 ff 0f 0f b7 c9 03 c1 8b 0d 90 01 04 01 08 83 45 90 01 01 02 4a 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_DelfInject_RT_MTB_2{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 2b 50 90 01 01 8b 45 90 01 01 8b 00 03 c7 8b 4d 90 01 01 66 8b 09 66 81 e1 ff 0f 0f b7 c9 03 c1 01 10 8b 45 90 01 01 83 c0 02 89 45 90 01 01 4b 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_DelfInject_RT_MTB_3{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 c4 f9 74 90 01 01 8b 4d 90 01 01 8b 49 90 01 01 8b 75 90 01 01 8b 76 90 01 01 03 0e 66 25 ff 0f 0f b7 c0 03 c8 8b 45 90 01 01 8b 40 90 01 01 01 01 83 03 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_DelfInject_RT_MTB_4{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 06 8b 00 25 ff ff 00 00 50 a1 90 01 04 50 e8 90 01 04 8b 16 89 02 eb 90 00 } //1
		$a_03_1 = {8b 06 83 c0 04 89 90 01 01 8b 90 01 01 8b 90 01 01 85 90 01 01 75 90 01 01 a1 90 01 04 83 c0 14 a3 90 01 04 a1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_DelfInject_RT_MTB_5{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 10 00 00 50 8d 04 9b 8b 44 c6 90 01 01 03 45 90 01 01 50 e8 90 00 } //1
		$a_03_1 = {f6 c4 f0 74 90 01 01 8b 5d 90 01 01 8b 5b 90 01 01 8b 75 90 01 01 8b 76 90 01 01 03 1e 66 25 ff 0f 0f b7 c0 03 d8 8b 45 90 01 01 8b 40 90 01 01 01 03 83 01 02 4a 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_DelfInject_RT_MTB_6{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 52 50 8b 43 90 01 01 99 03 04 24 13 54 24 90 01 01 83 c4 08 89 45 90 01 01 8b 45 90 01 01 89 48 90 00 } //1
		$a_03_1 = {0f b7 03 c1 e8 0c 83 f8 03 75 90 01 01 8b 45 90 01 01 8b d6 2b 50 90 01 01 8b 45 90 01 01 8b 00 03 c6 0f b7 0b 66 81 e1 ff 0f 0f b7 c9 03 c1 01 10 83 c3 02 4f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_DelfInject_RT_MTB_7{
	meta:
		description = "Trojan:Win32/DelfInject.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {f6 c4 f9 74 90 01 01 8b 4d 90 01 01 8b 49 90 01 01 8b 75 90 01 01 8b 76 90 01 01 03 0e 66 25 ff 0f 0f b7 c0 03 c8 8b 45 90 01 01 8b 40 90 01 01 01 01 8d 0c 03 8d 8b 90 02 1e 83 03 02 90 00 } //1
		$a_03_1 = {66 f7 c6 00 f9 74 90 01 01 8b 45 90 01 01 8b 40 90 01 01 8b 4d 90 01 01 8b 49 90 01 01 03 01 66 81 e6 ff 0f 0f b7 ce 03 c1 8b 4d 90 01 01 8b 49 90 01 01 01 08 83 03 02 4a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}