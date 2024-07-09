
rule Trojan_Win64_IcedID_MA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 83 c1 04 44 0f af 83 94 00 00 00 8b 43 6c 05 ?? ?? ?? ?? 03 c8 01 4a 2c 8b 83 a4 00 00 00 41 8b d0 33 05 ?? ?? ?? ?? 2d ?? ?? ?? ?? c1 ea 10 01 83 8c 00 00 00 48 63 8b 98 00 00 00 48 8b 83 c8 00 00 00 88 14 01 41 8b d0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win64_IcedID_MA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {31 74 33 45 6f 38 2e 64 6c 6c } //1 1t3Eo8.dll
		$a_01_2 = {44 6b 73 50 70 42 4b 75 71 } //1 DksPpBKuq
		$a_01_3 = {4c 51 79 68 73 43 64 6a 6c } //1 LQyhsCdjl
		$a_01_4 = {53 51 63 63 44 6d 4a 6c 68 45 } //1 SQccDmJlhE
		$a_01_5 = {56 6f 73 51 6c 42 72 58 } //1 VosQlBrX
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win64_IcedID_MA_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 69 44 61 62 72 } //2 AiDabr
		$a_01_1 = {42 49 78 6f 76 5a 4a } //2 BIxovZJ
		$a_01_2 = {42 61 30 55 54 32 35 35 } //2 Ba0UT255
		$a_01_3 = {43 48 55 37 5a 45 7a 47 52 69 } //2 CHU7ZEzGRi
		$a_01_4 = {43 6f 4f 63 4e 75 } //2 CoOcNu
		$a_01_5 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
		$a_01_6 = {52 61 73 47 65 74 43 72 65 64 65 6e 74 69 61 6c 73 41 } //1 RasGetCredentialsA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=12
 
}
rule Trojan_Win64_IcedID_MA_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 48 89 74 71 3e 4b 89 44 24 18 55 02 6f 59 48 8b ec 48 83 b9 4e 47 8b f9 4d 8b f1 ec 31 11 5a } //3
		$a_01_1 = {30 48 3b f9 27 25 84 42 40 48 03 c1 1d 15 f7 72 05 48 8b 12 be f0 47 85 c9 0f 84 f4 55 2e 0f 4c } //3
		$a_01_2 = {8b c0 4c 63 87 66 96 83 e2 03 48 03 97 ad ef 03 48 2b c2 48 36 e6 4e 0f b6 04 1a 44 5a 98 4b 0d } //3
		$a_81_3 = {69 6e 69 74 } //1 init
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_81_3  & 1)*1) >=10
 
}
rule Trojan_Win64_IcedID_MA_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_01_0 = {79 67 61 73 62 64 6a 6b 62 73 79 64 75 6a 68 61 6b 73 64 61 73 64 73 } //10 ygasbdjkbsydujhaksdasds
		$a_01_1 = {42 48 65 47 4c 44 4f 51 6e 70 43 53 79 4d 62 4d 71 45 74 4f } //5 BHeGLDOQnpCSyMbMqEtO
		$a_01_2 = {45 69 70 75 6a 62 4a 4e 4e 42 6a 76 4e 64 41 67 45 79 66 46 64 58 79 62 } //5 EipujbJNNBjvNdAgEyfFdXyb
		$a_01_3 = {46 45 69 6d 57 70 4a 75 54 71 64 4e 56 6b 41 67 41 47 75 47 79 48 } //5 FEimWpJuTqdNVkAgAGuGyH
		$a_01_4 = {4b 50 51 62 42 54 64 45 6f 43 53 70 6d 6b 4a 51 49 49 74 75 } //5 KPQbBTdEoCSpmkJQIItu
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=30
 
}
rule Trojan_Win64_IcedID_MA_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 61 79 75 66 62 61 73 75 66 79 67 61 6a 66 68 75 67 61 6a 73 61 73 66 } //1 sayufbasufygajfhugajsasf
		$a_01_1 = {4b 42 4e 4c 6f 6e 66 41 46 45 55 6d 48 71 67 } //1 KBNLonfAFEUmHqg
		$a_01_2 = {4b 42 64 57 73 53 6b 59 6b 48 59 77 7a } //1 KBdWsSkYkHYwz
		$a_01_3 = {4d 51 6e 6b 58 4e 67 77 71 72 43 64 4c 66 } //1 MQnkXNgwqrCdLf
		$a_01_4 = {51 61 70 55 4a 56 55 67 6e 73 41 4e 6e 6f 6e 50 } //1 QapUJVUgnsANnonP
		$a_01_5 = {51 72 53 6b 57 46 7a 78 70 6c 5a 52 53 6c } //1 QrSkWFzxplZRSl
		$a_01_6 = {4e 7a 74 64 6d 42 72 54 59 53 44 } //1 NztdmBrTYSD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}