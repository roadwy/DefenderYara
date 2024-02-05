
rule Trojan_Win32_Qakbot_GKM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 4d 1e 00 00 6a 00 e8 90 01 04 03 d8 01 1d 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 54 1b 00 00 6a 00 e8 90 01 04 03 d8 01 1d 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 e3 14 00 00 6a 00 e8 90 01 04 03 d8 01 1d 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 eb 14 00 00 6a 00 e8 90 01 04 03 d8 01 1d 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b7 f8 83 c6 43 8a 04 2a 88 02 8b c7 2b c1 42 83 c0 43 89 54 24 90 01 01 0f b7 c8 2b ce 83 c1 40 39 35 90 01 04 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 cf 0d 00 00 6a 00 e8 90 01 04 03 d8 01 5d 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 d7 11 00 00 6a 00 e8 90 01 04 8b d8 a1 90 01 04 8b 00 8b 15 90 01 04 03 55 90 01 01 03 55 90 01 01 33 c2 03 d8 68 d7 11 00 00 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 68 90 01 04 e8 90 01 04 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 01 04 68 d8 11 00 00 6a 00 e8 90 01 04 8b d8 a1 90 01 04 8b 00 03 45 90 01 01 03 d8 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 1c 17 a3 90 01 04 8b 3d 90 01 04 8b 94 0f 90 01 04 81 c2 f0 07 07 01 89 94 0f 90 01 04 83 c1 04 81 f9 80 05 00 00 8d 74 1e 90 01 01 89 15 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_12{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 db 03 fb 89 3d 90 01 04 8b 84 0e 90 01 04 05 4c 6a 06 01 a3 90 01 04 89 84 0e 90 01 04 83 c6 04 0f b7 05 90 01 04 05 da 9d 00 00 03 c7 81 fe 60 0b 00 00 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_13{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 01 04 68 57 15 00 00 6a 00 e8 90 01 04 8b 15 90 01 04 8b 12 03 55 90 01 01 03 c2 8b 15 90 01 04 89 02 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_14{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b d8 01 5d 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 e9 90 01 04 33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_15{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 55 90 01 01 03 55 90 01 01 03 55 90 01 01 33 c2 03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 89 18 a1 90 01 04 83 c0 04 a3 90 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_16{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_17{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 00 } //01 00 
		$a_02_1 = {8b d8 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 d8 e8 90 01 04 2b d8 a1 90 01 04 31 18 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_18{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 01 04 8b 45 90 01 01 8b 55 90 01 01 01 02 68 3b 11 00 00 6a 00 e8 90 01 04 8b d8 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 03 d8 68 3b 11 00 00 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_19{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b c8 8b 55 90 01 01 03 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 e8 90 01 04 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 eb 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_20{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 00 } //01 00 
		$a_02_1 = {2b d8 8b 45 90 01 01 89 18 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_21{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 2d 16 00 00 6a 00 e8 90 01 04 03 05 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 eb 90 00 } //01 00 
		$a_02_1 = {68 2d 16 00 00 6a 00 e8 90 01 04 8b d8 a1 90 01 04 8b 00 8b 15 90 01 04 81 c2 8a a5 08 00 03 55 90 01 01 33 c2 03 d8 68 2d 16 00 00 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_22{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 cf 0d 00 00 6a 00 e8 90 01 04 03 05 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 eb 90 00 } //01 00 
		$a_02_1 = {68 cf 0d 00 00 6a 00 e8 90 01 04 8b d8 a1 90 01 04 8b 00 8b 15 90 01 04 81 c2 8a a5 08 00 03 55 90 01 01 33 c2 03 d8 68 cf 0d 00 00 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_23{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 89 45 90 01 01 33 c9 8b 55 90 01 01 8b 45 90 01 01 e8 90 01 04 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 8b 55 90 01 01 03 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 4d 90 01 01 e8 90 01 04 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_24{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b d8 01 5d 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 e9 90 01 04 c7 45 a8 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 8b 45 90 01 01 8b 55 90 01 01 01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GKM_MTB_25{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b d8 01 5d 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 eb 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 8b 45 90 01 01 8b 55 90 01 01 01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}