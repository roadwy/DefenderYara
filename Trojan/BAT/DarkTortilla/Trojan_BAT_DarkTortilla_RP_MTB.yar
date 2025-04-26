
rule Trojan_BAT_DarkTortilla_RP_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 18 d8 1f 18 30 05 06 18 d8 2b 02 1f 18 0a 00 06 1f 18 5d 16 fe 01 0c 08 2c e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_2{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 20 c8 01 00 00 61 13 04 11 04 18 62 13 04 11 04 07 19 62 61 13 04 11 04 13 05 16 13 06 2b 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_3{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 0b 2b 0c 07 18 d8 1f 18 28 52 00 00 0a 0b 00 07 1f 18 5d 16 fe 01 0c 08 2c e9 07 0a 2b 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_4{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 19 5d 16 fe 01 13 07 11 07 2c 0d 06 11 06 06 11 06 91 1f 26 61 b4 9c 00 00 11 06 17 d6 13 06 11 06 11 05 31 d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_5{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 1d 5d 16 fe 01 13 07 11 07 2c 0d 06 11 06 06 11 06 91 1f 4a 61 b4 9c 00 00 11 06 17 d6 13 06 11 06 11 05 31 d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_6{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 18 0a 72 45 01 00 70 28 a7 00 00 06 0b 07 74 0c 00 00 1b 28 68 00 00 06 00 de 0f 25 28 38 00 00 0a 0c 00 28 52 00 00 0a de 00 00 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_7{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 19 d8 0a 06 1f 18 fe 02 0c 08 2c 0f 1f 18 0a 72 ?? ?? 00 70 28 ?? ?? 00 06 0b 00 00 00 06 1f 18 5d 16 fe 03 0d 09 2d d7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_8{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 8e 69 17 da 0b 16 0c 2b 1a 08 1b 5d 16 fe 01 0d 09 2c 0b 02 08 02 08 91 1f 32 61 b4 9c 00 00 08 17 d6 0c 08 07 31 e2 02 0a 2b 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_9{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2b 1e 06 19 d8 0a 06 1f 18 fe 02 0c 08 2c 0f 1f 18 0a 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b 00 00 00 06 1f 18 5d 16 fe ?? 0d 09 ?? d7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_10{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 17 da 17 d6 8d 03 00 00 01 0b 07 ?? 0a 00 00 1b 06 17 da 72 d0 2d 00 70 28 df 01 00 06 28 39 00 00 06 a2 07 74 0a 00 00 1b 06 28 b1 00 00 06 de 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_11{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 18 0a 72 ?? ?? 00 70 0c 08 72 ?? ?? 00 70 72 ?? ?? 00 70 6f ?? ?? 00 0a 28 ?? ?? 00 06 0b 07 74 ?? ?? 00 1b 28 ?? ?? 00 06 00 de 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_12{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 28 38 02 00 06 0b 07 06 17 da 72 d2 61 00 70 28 8d 00 00 06 28 33 02 00 06 a2 07 06 28 39 02 00 06 00 de 10 25 28 33 00 00 0a 13 05 00 28 85 00 00 0a de 00 00 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_13{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 0a 00 06 1f 18 fe 02 16 fe 01 0c 08 2c 06 1f 18 0a 00 2b 10 00 06 1f 18 fe 04 0d 09 2c 04 1f 18 0a 00 00 00 00 06 1f 18 5d 16 fe 01 13 04 11 04 2c cf 06 17 da 17 d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_14{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 06 17 8d 02 00 00 01 25 16 06 ?? ?? 00 00 01 a2 25 13 06 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 13 07 28 ?? 00 00 0a 13 08 [0-02] 13 0e 38 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_15{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 20 cc 00 00 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 06 0b 07 74 ?? ?? 00 1b 28 ?? ?? 00 06 00 de 0f 25 28 ?? ?? 00 0a 0c 00 28 ?? ?? 00 0a de 00 00 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_16{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 16 9a 14 [0-10] 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 17 8d ?? ?? 00 01 25 16 03 8c ?? ?? 00 01 a2 25 0b 14 14 17 8d ?? ?? 00 01 25 16 17 9c 25 0c 28 ?? ?? 00 0a 0d ?? 13 09 2b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_17{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 17 da 17 d6 8d ?? ?? 00 01 0c 72 ?? ?? 00 70 0d 09 28 ?? ?? 00 06 13 04 11 04 28 ?? ?? 00 06 13 05 08 06 17 da 11 05 28 ?? ?? 00 0a a2 08 06 28 ?? ?? 00 06 00 de 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_18{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 ec 01 00 06 28 37 00 00 0a 10 00 02 28 37 00 00 0a 28 ed 01 00 06 28 37 00 00 0a 0a 02 74 1c 00 00 01 06 28 69 00 00 0a 28 ee 01 00 06 28 05 01 00 06 28 3d 02 00 06 28 37 00 00 0a 28 19 02 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_19{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 14 72 ?? ?? 00 70 17 8d ?? ?? 00 01 25 16 06 72 ?? ?? 00 70 28 ?? ?? 00 0a a2 14 14 14 28 ?? ?? 00 0a 28 ?? ?? 00 0a 13 06 11 06 2c 0e 08 11 05 28 ?? ?? 00 0a 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_20{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 10 0a 06 17 da 06 28 ?? ?? 00 06 80 ?? ?? 00 04 06 20 ?? ?? 00 00 d8 80 ?? ?? 00 04 72 ?? ?? ?? ?? 28 ?? ?? 00 06 7e ?? ?? 00 04 28 ?? ?? 00 06 80 ?? ?? 00 04 28 ?? ?? 00 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_21{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 02 a2 25 17 16 ?? ?? ?? ?? ?? a2 25 18 02 8e 69 ?? ?? ?? ?? ?? a2 25 13 08 14 14 19 } //100
		$a_03_1 = {0d 07 06 17 da 09 28 ?? ?? ?? ?? a2 07 06 28 ?? ?? ?? ?? 00 de 1f } //100
		$a_01_2 = {2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 .g.resources
	condition:
		((#a_03_0  & 1)*100+(#a_03_1  & 1)*100+(#a_01_2  & 1)*1) >=101
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_22{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 ba 00 00 06 0a 06 2c 02 2b 01 00 00 73 24 00 00 0a 28 4d 00 00 0a 28 69 01 00 06 00 de 0f 25 28 47 00 00 0a 0b 00 28 60 00 00 0a de 00 00 2a } //10
		$a_01_1 = {00 28 6f 00 00 06 16 fe 01 0b 07 2c 04 17 0a 2b 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_23{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 17 da 17 d6 8d ?? ?? 00 01 0b 72 } //10
		$a_03_1 = {b7 0a 06 17 da 17 d6 8d ?? ?? 00 01 0b 20 ?? ?? ?? ?? 8c ?? ?? 00 01 0c 72 ?? ?? 00 70 72 ?? ?? 00 70 72 ?? ?? 00 70 28 } //10
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 41 00 70 00 70 00 31 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WindowsApp1.Resources
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_24{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 41 00 70 00 70 00 31 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //100 WindowsApp1.Resources
		$a_03_1 = {72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 [0-10] 2e 00 (70 00 6e 00 67 00|6a 00 70 00 67 00) } //10
		$a_03_2 = {1f 18 0a 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b } //10
		$a_01_3 = {2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 .g.resources
	condition:
		((#a_01_0  & 1)*100+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1) >=111
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_25{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 33 00 00 0a 0a 06 28 33 00 00 0a 28 ?? 01 00 06 de 0e 25 28 ?? 00 00 0a 0b 28 ?? 00 00 0a de 00 } //1
		$a_03_1 = {28 34 00 00 0a 0a 06 28 34 00 00 0a 28 ?? 01 00 06 de 0e 25 28 ?? 00 00 0a 0b 28 ?? 00 00 0a de 00 } //1
		$a_03_2 = {28 39 00 00 0a 0a 06 28 39 00 00 0a 28 ?? 01 00 06 00 de 0f 25 28 ?? 00 00 0a 0b 00 28 ?? 00 00 0a de 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_26{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,68 00 68 00 06 00 00 "
		
	strings :
		$a_03_0 = {0b 07 06 17 da 72 ?? ?? ?? ?? 28 } //100
		$a_03_1 = {0a 06 2c 02 2b 01 00 00 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 } //100
		$a_03_2 = {25 16 02 a2 0c 07 72 ?? ?? ?? ?? 20 00 01 00 00 14 14 08 6f } //100
		$a_03_3 = {a2 07 19 07 18 9a 74 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 } //100
		$a_01_4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 41 00 70 00 70 00 31 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WindowsApp1.Resources
		$a_01_5 = {2e 67 2e 72 65 73 6f 75 72 63 65 73 } //3 .g.resources
	condition:
		((#a_03_0  & 1)*100+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100+(#a_03_3  & 1)*100+(#a_01_4  & 1)*1+(#a_01_5  & 1)*3) >=104
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_27{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,6a 00 6a 00 07 00 00 "
		
	strings :
		$a_03_0 = {00 1b 19 9a 28 ?? 00 00 0a 28 ?? ?? 00 06 26 de } //100
		$a_01_1 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //1 Create__Instance__
		$a_01_2 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //1 Dispose__Instance__
		$a_01_3 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_01_4 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //1 GetResourceString
		$a_01_5 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //1 CryptoStreamMode
		$a_80_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
	condition:
		((#a_03_0  & 1)*100+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_80_6  & 1)*1) >=106
 
}
rule Trojan_BAT_DarkTortilla_RP_MTB_28{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff94 00 ffffff94 00 10 00 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //1 CryptoStreamMode
		$a_01_1 = {45 6e 64 49 6e 76 6f 6b 65 } //1 EndInvoke
		$a_01_2 = {42 65 67 69 6e 49 6e 76 6f 6b 65 } //1 BeginInvoke
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {67 65 74 5f 4b 65 79 } //1 get_Key
		$a_01_5 = {73 65 74 5f 4b 65 79 } //1 set_Key
		$a_01_6 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //1 ContainsKey
		$a_01_7 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_01_8 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //10 Create__Instance__
		$a_01_9 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //10 Dispose__Instance__
		$a_01_10 = {43 6f 6e 6e 65 63 74 69 6f 6e 54 65 73 74 65 72 } //100 ConnectionTester
		$a_01_11 = {54 65 73 74 43 6f 6e 6e 65 63 74 69 6f 6e 20 4c 61 6e 73 77 65 65 70 65 72 } //10 TestConnection Lansweeper
		$a_01_12 = {2c 20 57 69 6e 64 6f 77 73 41 70 70 31 2c } //10 , WindowsApp1,
		$a_01_13 = {57 69 6e 64 6f 77 73 41 70 70 31 2e 57 65 61 74 68 65 72 41 70 70 2b } //100 WindowsApp1.WeatherApp+
		$a_01_14 = {57 69 6e 64 6f 77 73 41 70 70 31 2e 41 69 72 70 6c 61 6e 65 57 65 61 74 68 65 72 43 6f 6e 74 72 6f 6c 2b } //10 WindowsApp1.AirplaneWeatherControl+
		$a_01_15 = {57 69 6e 64 6f 77 73 41 70 70 31 2e 4d 4c 57 65 61 74 68 65 72 46 6f 72 65 63 61 73 74 2b } //10 WindowsApp1.MLWeatherForecast+
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*100+(#a_01_11  & 1)*10+(#a_01_12  & 1)*10+(#a_01_13  & 1)*100+(#a_01_14  & 1)*10+(#a_01_15  & 1)*10) >=148
 
}