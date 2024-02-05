
rule Trojan_Win32_Qbot_MX_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b ff 8b ff 8b ff 33 c1 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d8 33 d9 8b ff c7 05 90 01 04 00 00 00 00 01 1d 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //01 00 
		$a_80_1 = {31 36 72 74 75 2e 6c 41 6c 2b 6f 63 } //16rtu.lAl+oc  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 ec a3 90 01 04 e8 90 01 04 b9 39 00 00 00 85 c9 0f 85 90 00 } //01 00 
		$a_02_1 = {68 03 5f 00 00 ff 15 90 01 04 05 c2 5a 00 00 8b 4d 90 01 01 8b 11 2b d0 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 11 88 10 8b 45 90 01 01 83 c0 01 89 45 90 00 } //01 00 
		$a_02_1 = {83 c0 04 89 45 90 01 03 e8 90 01 04 8b 4d 90 01 01 3b 0d 90 01 04 72 90 01 03 ba 18 30 00 00 85 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_5{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 11 88 14 30 8b 45 90 01 01 83 c0 01 89 45 90 00 } //01 00 
		$a_02_1 = {83 c0 04 89 45 90 01 01 e8 90 01 04 8b 4d 90 01 01 3b 0d 90 01 04 72 90 01 03 ba 34 0e 00 00 85 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 08 88 0a 8b 55 90 01 01 83 c2 01 89 55 90 01 01 eb 90 00 } //01 00 
		$a_02_1 = {83 c0 04 89 45 90 01 01 e8 90 01 04 8b 4d 90 01 01 3b 0d 90 01 04 72 90 01 03 ba 18 30 00 00 85 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_7{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 00 88 04 11 8b 4d 90 01 01 83 c1 01 89 4d 90 00 } //01 00 
		$a_02_1 = {83 c0 04 89 45 90 01 01 e8 90 01 04 8b 4d 90 01 01 3b 0d 90 01 04 72 90 01 01 eb 90 01 01 ba 9c ad 00 00 85 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_8{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {ba be 15 00 00 ba be 15 00 00 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff 8b 15 90 01 04 a1 90 01 04 89 02 90 00 } //01 00 
		$a_80_1 = {77 32 33 34 7b 36 37 38 6f 30 31 32 55 34 } //w234{678o012U4  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_9{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 00 88 04 11 8b 4d 90 01 01 83 c1 01 89 4d f8 90 00 } //01 00 
		$a_02_1 = {83 c0 04 89 45 90 01 01 e8 90 01 04 8b 4d 90 01 01 3b 0d 90 01 04 72 90 01 01 eb 90 01 01 ba 1f de 01 00 85 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_10{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 06 88 04 0a 8b 4d 90 01 01 83 c1 01 89 4d 90 00 } //01 00 
		$a_02_1 = {8b 55 ec 89 15 90 01 04 e8 90 01 04 8b 45 90 01 01 3b 05 90 01 04 72 90 01 01 eb 90 01 01 b9 39 00 00 00 85 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_11{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 00 88 04 11 8b 4d 90 01 01 83 c1 01 89 4d 90 00 } //01 00 
		$a_02_1 = {83 c0 04 89 45 90 01 01 eb 90 01 01 e8 90 01 04 8b 4d 90 01 01 3b 0d 90 01 04 72 90 01 01 eb 90 01 01 ba 39 00 00 00 85 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_12{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 09 88 0c 02 8b 55 90 01 01 83 c2 01 89 55 90 01 01 eb c7 90 00 } //01 00 
		$a_02_1 = {8b 55 ec 89 15 90 01 04 e8 90 01 04 8b 45 90 01 01 3b 05 90 01 04 72 90 01 01 eb 90 01 01 b9 39 00 00 00 85 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_MX_MTB_13{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {5b d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 90 01 01 81 90 02 05 33 90 02 02 83 90 02 02 6a 00 89 90 02 02 29 d2 31 da 89 d0 5a aa 49 75 90 00 } //01 00 
		$a_02_1 = {89 fa 5f 6a 90 01 01 8f 90 01 02 d3 c0 8a fc 8a e6 d3 cb ff 90 01 02 75 90 01 01 8f 90 01 02 8b 90 01 02 56 83 90 01 02 31 90 01 01 83 90 01 02 31 90 01 01 5e aa 49 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}