
rule Trojan_Win32_Azorult_RT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 9c 06 00 00 74 ?? 40 89 45 ?? 3d 81 84 13 01 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ca 33 c8 [0-0a] a3 01 00 00 c7 [0-05] ee 3d ea f4 89 [0-05] 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 ?? 8d 4d [0-05] c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 ?? 8b ?? ?? 01 ?? ?? c7 [0-05] 64 61 15 fe 81 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 ?? 8b ?? ?? 01 ?? ?? c7 [0-05] 64 61 15 fe 8b ?? ?? 81 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fc 03 cf ff [0-1e] 1b 75 90 09 3c 00 [0-3c] d3 [0-09] 89 [0-1e] 89 [0-1e] c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 fb 61 36 13 01 0f [0-05] eb ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 ff 81 ff cb 04 00 00 7d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_8{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 ?? ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 8b ?? ?? ?? ?? ?? 01 ?? ?? 81 ?? ?? ?? ?? ?? d0 04 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_9{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b ?? ?? 33 cb 33 ?? ?? 8d ?? ?? ?? ?? ?? 89 ?? ?? e8 ?? ?? ?? ?? 89 ?? ?? 25 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Azorult_RT_MTB_10{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 eb c7 05 ?? ?? ?? ?? 2e ce 50 91 89 45 ?? 03 9d ?? ?? ?? ?? 33 d8 81 3d ?? ?? ?? ?? b7 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_11{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f0 89 45 ?? 89 75 ?? 8b 45 ?? 29 45 ?? 25 bb 52 c0 5d 8b 55 ?? 8b c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_12{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ec 1c 04 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 ?? ?? ?? ?? a1 [0-0a] 8b 3d ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 f6 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_13{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 fd 9d 06 00 00 74 ?? 45 81 fd 61 36 13 01 0f [0-05] eb [0-05] a1 [0-05] a3 [0-05] 33 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_14{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b 85 ?? ?? ?? ?? 8d 0c 18 8b 85 ?? ?? ?? ?? 33 c1 31 45 ?? 81 3d ?? ?? ?? ?? a3 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_15{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 89 ?? ?? 8b ?? ?? 01 ?? ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? e4 fa d6 cb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_16{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 ?? ?? 8b ?? ?? 01 ?? ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? 81 ?? ?? ?? ?? ?? 96 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_17{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 89 [0-05] 8b [0-05] 01 [0-05] 8b [0-05] 03 [0-05] 89 [0-05] 81 [0-05] be 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_18{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 45 ?? 03 ?? ?? 33 d0 89 ?? ?? 8b ?? ?? 29 ?? ?? 25 bb 52 c0 5d 8b ?? ?? 8b c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_19{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c7 05 ?? ?? ?? ?? 2e ce 50 91 e8 ?? ?? ?? ?? 8b ?? ?? d3 ee 89 ?? ?? 03 ?? ?? 33 f0 2b fe 25 bb 52 c0 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_20{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c7 05 ?? ?? ?? ?? 2e ce 50 91 e8 ?? ?? ?? ?? 8b 4d ?? 8b fe d3 ef 03 7d ?? 33 f8 81 fa 8f 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_21{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 89 4d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 55 ?? 03 d0 81 3d ?? ?? ?? ?? be 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_22{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 ?? 8b ?? ?? 01 ?? ?? c7 ?? ?? ?? ?? ?? 64 61 15 fe 8b ?? ?? 81 ?? ?? ?? ?? ?? 9c 9e ea 01 01 ?? ?? ?? ?? ?? 83 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_23{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 e0 89 45 ?? c7 ?? ?? ?? ?? ?? 82 cd 10 fe 8b ?? ?? 81 ?? ?? ?? ?? ?? 7e 32 ef 01 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 ?? ?? 89 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_24{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 55 e0 89 55 ?? c7 ?? ?? ?? ?? ?? 36 06 ea e9 8b ?? ?? 81 ?? ?? ?? ?? ?? ca f9 15 16 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 [0-05] 89 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_25{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4d ?? 03 ce 51 03 55 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 89 55 ?? e8 ?? ?? ?? ?? 89 45 ?? 81 fb e6 09 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_26{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c5 33 44 24 ?? c7 05 [0-0a] 89 44 24 ?? 8b 44 24 ?? 01 05 ?? ?? ?? ?? 2b 74 24 ?? c7 05 ?? ?? ?? ?? b4 21 e1 c5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_27{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 86 76 13 01 89 44 24 ?? 0f 8c ?? ?? ?? ?? eb ?? 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 7c 24 ?? 8b 1d ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 33 f6 81 fe 13 4d 00 00 7d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_28{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e ce 50 91 e8 ?? ?? ?? ?? 8b [0-05] 8b [0-0a] d3 [0-05] 03 [0-05] 33 [0-0a] 8f 01 00 00 75 } //1
		$a_03_1 = {25 bb 52 c0 5d 8b 45 ?? 03 c3 50 8b c3 c1 e0 04 03 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_29{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {d3 eb c7 05 ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 83 } //1
		$a_03_1 = {d3 ef c7 05 ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 83 } //1
		$a_03_2 = {d3 eb 89 45 ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 83 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RT_MTB_30{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? ?? ?? e4 ?? ?? f0 89 ?? ?? ?? ?? ec 31 ?? ?? ?? ?? e4 29 ?? ?? 81 [0-06] 17 04 00 00 } //1
		$a_03_1 = {03 c3 89 45 ?? c7 [0-0a] 8b [0-0a] 8d [0-0a] e8 ?? ?? ?? ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? fc 03 cf ff 83 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}