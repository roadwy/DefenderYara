
rule Trojan_Win32_Fragtor_NF_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 0d 53 e8 ?? ?? ?? ?? 59 85 c0 75 a9 eb 07 e8 ?? ?? ?? ?? 89 30 e8 d4 0e 00 00 89 30 8b c7 5f } //5
		$a_01_1 = {57 6b 56 32 31 54 53 61 76 } //1 WkV21TSav
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Fragtor_NF_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {a1 c8 4f 46 00 6b c9 ?? 03 c8 eb 11 8b 55 ?? 2b 50 0c 81 fa 00 00 10 00 72 09 83 c0 ?? 3b c1 72 eb 33 c0 } //5
		$a_01_1 = {47 5a 47 4c 58 54 } //1 GZGLXT
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Fragtor_NF_MTB_3{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {6c 69 62 79 75 67 76 38 36 2e 64 6c 6c } //5 libyugv86.dll
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 70 75 62 6c 75 62 5c 44 75 76 41 70 70 } //5 Software\publub\DuvApp
		$a_81_2 = {67 63 72 79 5f 6d 64 5f 73 65 74 6b 65 79 } //2 gcry_md_setkey
		$a_81_3 = {54 72 69 61 6c 45 78 70 69 72 65 } //2 TrialExpire
		$a_81_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1) >=15
 
}
rule Trojan_Win32_Fragtor_NF_MTB_4{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {4c 65 76 65 72 61 67 69 6e 67 20 44 4b 4f 4d 20 74 6f 20 61 63 68 69 65 76 65 20 4c 50 45 } //2 Leveraging DKOM to achieve LPE
		$a_01_1 = {43 61 6c 6c 69 6e 67 20 57 72 69 74 65 36 34 20 77 72 61 70 70 65 72 20 74 6f 20 6f 76 65 72 77 72 69 74 65 20 63 75 72 72 65 6e 74 20 45 50 52 4f 43 45 53 53 2d 3e 54 6f 6b 65 6e } //2 Calling Write64 wrapper to overwrite current EPROCESS->Token
		$a_01_2 = {44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4d 00 75 00 70 00 5c 00 3b 00 43 00 73 00 63 00 5c 00 2e 00 5c 00 2e 00 } //1 Device\Mup\;Csc\.\.
		$a_01_3 = {43 75 72 72 65 6e 74 20 45 50 52 4f 43 45 53 53 20 61 64 64 72 65 73 73 } //1 Current EPROCESS address
		$a_01_4 = {43 75 72 72 65 6e 74 20 54 48 52 45 41 44 20 61 64 64 72 65 73 73 } //1 Current THREAD address
		$a_01_5 = {53 79 73 74 65 6d 20 45 50 52 4f 43 45 53 53 20 61 64 64 72 65 73 73 } //1 System EPROCESS address
		$a_01_6 = {63 6d 64 2e 65 78 65 } //1 cmd.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}
rule Trojan_Win32_Fragtor_NF_MTB_5{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 00 45 00 54 00 43 00 45 00 4a 00 45 00 4e 00 49 00 57 00 20 00 74 00 72 00 6f 00 6a 00 61 00 6e 00 20 00 73 00 65 00 74 00 75 00 70 00 } //2 DETCEJENIW trojan setup
		$a_01_1 = {54 00 68 00 65 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 79 00 6f 00 75 00 20 00 6a 00 75 00 73 00 74 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 64 00 20 00 69 00 73 00 20 00 63 00 6f 00 6e 00 73 00 69 00 64 00 65 00 72 00 65 00 64 00 20 00 6d 00 61 00 6c 00 77 00 61 00 72 00 65 00 } //2 The software you just executed is considered malware
		$a_01_2 = {54 00 68 00 69 00 73 00 20 00 6d 00 61 00 6c 00 77 00 61 00 72 00 65 00 20 00 77 00 69 00 6c 00 6c 00 20 00 68 00 61 00 72 00 6d 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 61 00 6e 00 64 00 20 00 6d 00 61 00 6b 00 65 00 73 00 20 00 69 00 74 00 20 00 75 00 6e 00 75 00 73 00 61 00 62 00 6c 00 65 00 } //1 This malware will harm your computer and makes it unusable
		$a_01_3 = {49 00 66 00 20 00 79 00 6f 00 75 00 20 00 6b 00 6e 00 6f 00 77 00 20 00 77 00 68 00 61 00 74 00 20 00 74 00 68 00 69 00 73 00 20 00 6d 00 61 00 6c 00 77 00 61 00 72 00 65 00 20 00 64 00 6f 00 65 00 73 00 20 00 61 00 6e 00 64 00 20 00 61 00 72 00 65 00 20 00 75 00 73 00 69 00 6e 00 67 00 20 00 61 00 20 00 73 00 61 00 66 00 65 00 20 00 65 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 20 00 74 00 6f 00 20 00 74 00 65 00 73 00 74 00 2c 00 20 00 70 00 72 00 65 00 73 00 73 00 20 00 59 00 65 00 73 00 20 00 74 00 6f 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 69 00 74 00 } //1 If you know what this malware does and are using a safe environment to test, press Yes to start it
		$a_01_4 = {54 00 48 00 45 00 20 00 43 00 52 00 45 00 41 00 54 00 4f 00 52 00 20 00 49 00 53 00 20 00 4e 00 4f 00 54 00 20 00 52 00 45 00 53 00 50 00 4f 00 4e 00 53 00 49 00 42 00 4c 00 45 00 20 00 46 00 4f 00 52 00 20 00 41 00 4e 00 59 00 20 00 44 00 41 00 4d 00 41 00 47 00 45 00 20 00 4d 00 41 00 44 00 45 00 20 00 55 00 53 00 49 00 4e 00 47 00 20 00 54 00 48 00 49 00 53 00 20 00 4d 00 41 00 4c 00 57 00 41 00 52 00 45 00 21 00 } //1 THE CREATOR IS NOT RESPONSIBLE FOR ANY DAMAGE MADE USING THIS MALWARE!
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}