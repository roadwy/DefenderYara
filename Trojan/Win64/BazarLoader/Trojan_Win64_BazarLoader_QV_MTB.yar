
rule Trojan_Win64_BazarLoader_QV_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.QV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {0f b6 04 01 6b c0 71 83 c0 26 99 b9 7f 00 00 00 f7 f9 8b c2 48 8b 4c 24 28 88 01 } //01 00 
		$a_80_1 = {50 61 75 73 65 57 } //PauseW  01 00 
		$a_80_2 = {52 65 73 75 6d 65 53 65 72 76 65 72 } //ResumeServer  01 00 
		$a_80_3 = {52 65 73 75 6d 65 57 } //ResumeW  01 00 
		$a_80_4 = {53 74 61 72 74 53 65 72 76 65 72 } //StartServer  01 00 
		$a_80_5 = {53 74 61 72 74 57 } //StartW  01 00 
		$a_80_6 = {53 74 6f 70 53 65 72 76 65 72 } //StopServer  01 00 
		$a_80_7 = {53 75 73 70 65 6e 64 53 65 72 76 65 72 } //SuspendServer  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BazarLoader_QV_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.QV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {49 87 dd 4c 89 6c 24 08 49 87 dd 49 87 ed 4c 89 6c 24 10 4c 87 ed 48 89 74 24 18 48 87 f9 48 89 4c 24 20 48 87 f9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BazarLoader_QV_MTB_3{
	meta:
		description = "Trojan:Win64/BazarLoader.QV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 0d 8b ca 41 ff c0 c1 e9 10 88 08 48 ff c0 49 63 c8 48 3b ce 73 0d 8b ca 41 ff c0 c1 e9 08 88 08 48 ff c0 49 63 c8 48 3b ce 73 08 41 ff c0 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BazarLoader_QV_MTB_4{
	meta:
		description = "Trojan:Win64/BazarLoader.QV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 85 7e 01 00 00 8a 8d 7f 01 00 00 88 ca 80 f2 ff 41 88 c0 41 30 d0 41 20 c0 88 c2 80 f2 ff 41 88 c9 41 20 d1 80 f1 ff 20 c8 41 08 c1 44 88 c0 34 ff 44 88 c9 80 f1 ff b2 01 80 f2 01 41 88 c2 41 80 e2 ff 41 20 d0 41 88 cb 41 80 e3 ff 41 20 d1 45 08 c2 45 08 cb 45 30 da 08 c8 } //00 00 
	condition:
		any of ($a_*)
 
}