
rule Trojan_Win32_AgentTesla_A_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {72 6f 6f 74 5c 63 69 6d 76 32 } //1 root\cimv2
		$a_81_1 = {55 73 65 72 6e 61 6d 65 3a } //1 Username:
		$a_81_2 = {50 61 73 73 77 6f 72 64 3a } //1 Password:
		$a_81_3 = {77 6f 72 6c 6f 72 64 65 72 62 69 6c 6c 69 6f 6e 73 2e 74 6f 70 } //1 worlorderbillions.top
		$a_81_4 = {6e 69 67 67 61 62 6f 77 6e 32 32 6a 61 6e 32 30 32 34 } //1 niggabown22jan2024
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_AgentTesla_A_MTB_2{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {64 ff 30 64 89 20 ff 05 ?? ?? ?? 00 75 ?? 83 3d ?? ?? ?? 00 00 74 0a a1 ?? ?? ?? 00 e8 } //1
		$a_02_1 = {8b c7 8b de 8b d3 90 05 10 01 90 e8 ?? ?? ?? ?? 90 05 10 01 90 46 90 05 10 01 90 81 fe ?? ?? 00 00 75 } //1
		$a_02_2 = {8b c8 03 ca 8b c2 b2 ?? 32 90 90 ?? ?? ?? 00 88 11 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule Trojan_Win32_AgentTesla_A_MTB_3{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 6c 2e 4f 0e 53 43 29 7b bc 63 67 b2 6f 63 2f eb 17 06 8a 32 7f f1 13 5f d2 e1 47 39 d2 2b 3d 53 56 11 bf 10 ea 03 36 45 12 c7 4d 89 6c 25 ce } //10
		$a_01_1 = {2e 76 6d 5f 73 65 63 } //1 .vm_sec
		$a_01_2 = {2e 74 68 65 6d 69 64 61 } //1 .themida
		$a_01_3 = {43 00 68 00 6f 00 2d 00 43 00 68 00 75 00 6e 00 20 00 48 00 75 00 61 00 6e 00 67 00 } //1 Cho-Chun Huang
		$a_01_4 = {2f 63 68 65 63 6b 70 72 6f 74 65 63 74 69 6f 6e } //1 /checkprotection
		$a_01_5 = {65 00 2d 00 43 00 68 00 69 00 6e 00 61 00 20 00 50 00 65 00 74 00 72 00 6f 00 6c 00 65 00 75 00 6d 00 20 00 26 00 20 00 43 00 68 00 65 00 6d 00 69 00 63 00 61 00 6c 00 20 00 43 00 6f 00 72 00 70 00 } //1 e-China Petroleum & Chemical Corp
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win32_AgentTesla_A_MTB_4{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 "
		
	strings :
		$a_81_0 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //1 get_Password
		$a_81_1 = {73 65 74 5f 50 61 73 73 77 6f 72 64 } //1 set_Password
		$a_81_2 = {44 6f 6d 61 69 6e 50 61 73 73 77 6f 72 64 } //1 DomainPassword
		$a_81_3 = {53 6d 74 70 50 61 73 73 77 6f 72 64 } //1 SmtpPassword
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_6 = {45 6e 63 50 61 73 73 77 6f 72 64 } //1 EncPassword
		$a_81_7 = {44 69 73 63 6f 72 64 20 54 6f 6b 65 6e } //1 Discord Token
		$a_81_8 = {5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \Login Data
		$a_81_9 = {5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \Default\Login Data
		$a_81_10 = {28 68 6f 73 74 6e 61 6d 65 7c 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 7c 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 29 } //1 (hostname|encryptedPassword|encryptedUsername)
		$a_81_11 = {3b 50 6f 72 74 3d } //1 ;Port=
		$a_81_12 = {46 6f 78 4d 61 69 6c } //1 FoxMail
		$a_81_13 = {5c 6d 61 69 6c } //1 \mail
		$a_81_14 = {49 63 65 44 72 61 67 6f 6e } //1 IceDragon
		$a_81_15 = {5c 4e 45 54 47 41 54 45 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 5c 42 6c 61 63 6b 48 61 77 6b } //1 \NETGATE Technologies\BlackHawk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1) >=16
 
}
rule Trojan_Win32_AgentTesla_A_MTB_5{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 51 fa f1 4b 6d ec fb 9f d9 6f 9b ea 37 df 0a 80 13 27 4e fa a3 a0 96 47 d9 8b d6 a9 75 17 02 40 3d a9 37 f5 18 65 2f 1a 03 8d 85 c6 44 63 43 00 a0 22 e5 06 40 4b f3 0e 53 69 e3 d2 91 26 8e da db fe a4 ed de d5 6a cd db 5b ac d0 4f 5b eb 1e ff 7a 1c bd 68 dd 85 3e d4 93 7a 8b a3 97 42 69 6c 0a fd 10 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}