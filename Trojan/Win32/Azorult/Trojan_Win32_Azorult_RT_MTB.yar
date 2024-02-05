
rule Trojan_Win32_Azorult_RT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 9c 06 00 00 74 90 01 01 40 89 45 90 01 01 3d 81 84 13 01 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 ca 33 c8 90 02 0a a3 01 00 00 c7 90 02 05 ee 3d ea f4 89 90 02 05 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 90 01 01 8d 4d 90 02 05 c7 05 90 01 04 b4 02 d7 cb c7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 90 01 01 8b 90 01 02 01 90 01 02 c7 90 02 05 64 61 15 fe 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 90 01 01 8b 90 01 02 01 90 01 02 c7 90 02 05 64 61 15 fe 8b 90 01 02 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {fc 03 cf ff 90 02 1e 1b 75 90 09 3c 00 90 02 3c d3 90 02 09 89 90 02 1e 89 90 02 1e c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 fb 61 36 13 01 0f 90 02 05 eb 90 01 01 a1 90 01 04 a3 90 01 04 33 ff 81 ff cb 04 00 00 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_8{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 90 01 02 c7 90 01 05 2e ce 50 91 8b 90 01 05 01 90 01 02 81 90 01 05 d0 04 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_9{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b 90 01 02 33 cb 33 90 01 02 8d 90 01 05 89 90 01 02 e8 90 01 04 89 90 01 02 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_10{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 eb c7 05 90 01 04 2e ce 50 91 89 45 90 01 01 03 9d 90 01 04 33 d8 81 3d 90 01 04 b7 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_11{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f0 89 45 90 01 01 89 75 90 01 01 8b 45 90 01 01 29 45 90 01 01 25 bb 52 c0 5d 8b 55 90 01 01 8b c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_12{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 ec 1c 04 00 00 a1 90 01 04 33 c4 89 84 24 90 01 04 a1 90 02 0a 8b 3d 90 01 04 a3 90 01 04 33 f6 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_13{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 fd 9d 06 00 00 74 90 01 01 45 81 fd 61 36 13 01 0f 90 02 05 eb 90 02 05 a1 90 02 05 a3 90 02 05 33 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_14{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b 85 90 01 04 8d 0c 18 8b 85 90 01 04 33 c1 31 45 90 01 01 81 3d 90 01 04 a3 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_15{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 89 90 01 02 8b 90 01 02 01 90 01 02 8b 90 01 02 03 90 01 02 89 90 01 02 c7 90 01 05 e4 fa d6 cb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_16{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 90 01 02 8b 90 01 02 01 90 01 02 8b 90 01 02 03 90 01 02 89 90 01 02 81 90 01 05 96 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_17{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 89 90 02 05 8b 90 02 05 01 90 02 05 8b 90 02 05 03 90 02 05 89 90 02 05 81 90 02 05 be 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_18{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 45 90 01 01 03 90 01 02 33 d0 89 90 01 02 8b 90 01 02 29 90 01 02 25 bb 52 c0 5d 8b 90 01 02 8b c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_19{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 c7 05 90 01 04 2e ce 50 91 e8 90 01 04 8b 90 01 02 d3 ee 89 90 01 02 03 90 01 02 33 f0 2b fe 25 bb 52 c0 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_20{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 c7 05 90 01 04 2e ce 50 91 e8 90 01 04 8b 4d 90 01 01 8b fe d3 ef 03 7d 90 01 01 33 f8 81 fa 8f 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_21{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 89 4d 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 8b 55 90 01 01 03 d0 81 3d 90 01 04 be 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_22{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 90 01 01 8b 90 01 02 01 90 01 02 c7 90 01 05 64 61 15 fe 8b 90 01 02 81 90 01 05 9c 9e ea 01 01 90 01 05 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_23{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 45 e0 89 45 90 01 01 c7 90 01 05 82 cd 10 fe 8b 90 01 02 81 90 01 05 7e 32 ef 01 01 90 01 05 8b 90 01 02 33 90 01 02 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_24{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 55 e0 89 55 90 01 01 c7 90 01 05 36 06 ea e9 8b 90 01 02 81 90 01 05 ca f9 15 16 01 90 01 05 8b 90 01 02 33 90 02 05 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_25{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4d 90 01 01 03 ce 51 03 55 90 01 01 c7 05 90 01 04 2e ce 50 91 89 55 90 01 01 e8 90 01 04 89 45 90 01 01 81 fb e6 09 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_26{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c5 33 44 24 90 01 01 c7 05 90 02 0a 89 44 24 90 01 01 8b 44 24 90 01 01 01 05 90 01 04 2b 74 24 90 01 01 c7 05 90 01 04 b4 21 e1 c5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_27{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 86 76 13 01 89 44 24 90 01 01 0f 8c 90 01 04 eb 90 01 01 8b 15 90 01 04 89 15 90 01 04 8b 7c 24 90 01 01 8b 1d 90 01 04 8b 2d 90 01 04 33 f6 81 fe 13 4d 00 00 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_28{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e ce 50 91 e8 90 01 04 8b 90 02 05 8b 90 02 0a d3 90 02 05 03 90 02 05 33 90 02 0a 8f 01 00 00 75 90 00 } //01 00 
		$a_03_1 = {25 bb 52 c0 5d 8b 45 90 01 01 03 c3 50 8b c3 c1 e0 04 03 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_29{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 eb c7 05 90 01 04 2e ce 50 91 89 90 01 02 8b 90 01 02 01 90 01 02 83 90 00 } //01 00 
		$a_03_1 = {d3 ef c7 05 90 01 04 2e ce 50 91 89 90 01 02 8b 90 01 02 01 90 01 02 83 90 00 } //01 00 
		$a_03_2 = {d3 eb 89 45 90 01 01 c7 90 01 05 2e ce 50 91 89 90 01 02 8b 90 01 02 01 90 01 02 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RT_MTB_30{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 90 01 01 8b 90 01 02 03 90 01 02 89 90 01 04 e4 90 01 02 f0 89 90 01 04 ec 31 90 01 04 e4 29 90 01 02 81 90 02 06 17 04 00 00 90 00 } //01 00 
		$a_03_1 = {03 c3 89 45 90 01 01 c7 90 02 0a 8b 90 02 0a 8d 90 02 0a e8 90 01 04 8b 90 01 02 03 90 01 02 89 90 01 02 c7 90 01 05 fc 03 cf ff 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}