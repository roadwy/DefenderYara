
rule Trojan_Win32_Qbot_MX_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ff 8b ff 8b ff 33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d8 33 d9 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 } //1
		$a_80_1 = {31 36 72 74 75 2e 6c 41 6c 2b 6f 63 } //16rtu.lAl+oc  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_MX_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 ec a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 39 00 00 00 85 c9 0f 85 } //1
		$a_02_1 = {68 03 5f 00 00 ff 15 ?? ?? ?? ?? 05 c2 5a 00 00 8b 4d ?? 8b 11 2b d0 8b 45 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_MX_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 11 88 10 8b 45 ?? 83 c0 01 89 45 } //1
		$a_02_1 = {83 c0 04 89 45 ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? ?? ?? ba 18 30 00 00 85 d2 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_MX_MTB_5{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 11 88 14 30 8b 45 ?? 83 c0 01 89 45 } //1
		$a_02_1 = {83 c0 04 89 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? ?? ?? ba 34 0e 00 00 85 d2 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_MX_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 08 88 0a 8b 55 ?? 83 c2 01 89 55 ?? eb } //1
		$a_02_1 = {83 c0 04 89 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? ?? ?? ba 18 30 00 00 85 d2 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_MX_MTB_7{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 00 88 04 11 8b 4d ?? 83 c1 01 89 4d } //1
		$a_02_1 = {83 c0 04 89 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? ba 9c ad 00 00 85 d2 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_MX_MTB_8{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {ba be 15 00 00 ba be 15 00 00 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 } //1
		$a_80_1 = {77 32 33 34 7b 36 37 38 6f 30 31 32 55 34 } //w234{678o012U4  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_MX_MTB_9{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 00 88 04 11 8b 4d ?? 83 c1 01 89 4d f8 } //1
		$a_02_1 = {83 c0 04 89 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? ba 1f de 01 00 85 d2 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_MX_MTB_10{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 04 06 88 04 0a 8b 4d ?? 83 c1 01 89 4d } //1
		$a_02_1 = {8b 55 ec 89 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? 3b 05 ?? ?? ?? ?? 72 ?? eb ?? b9 39 00 00 00 85 c9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_MX_MTB_11{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 00 88 04 11 8b 4d ?? 83 c1 01 89 4d } //1
		$a_02_1 = {83 c0 04 89 45 ?? eb ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? ba 39 00 00 00 85 d2 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_MX_MTB_12{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 09 88 0c 02 8b 55 ?? 83 c2 01 89 55 ?? eb c7 } //1
		$a_02_1 = {8b 55 ec 89 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? 3b 05 ?? ?? ?? ?? 72 ?? eb ?? b9 39 00 00 00 85 c9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_MX_MTB_13{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {5b d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 ?? 81 [0-05] 33 [0-02] 83 [0-02] 6a 00 89 [0-02] 29 d2 31 da 89 d0 5a aa 49 75 } //1
		$a_02_1 = {89 fa 5f 6a ?? 8f ?? ?? d3 c0 8a fc 8a e6 d3 cb ff ?? ?? 75 ?? 8f ?? ?? 8b ?? ?? 56 83 ?? ?? 31 ?? 83 ?? ?? 31 ?? 5e aa 49 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}