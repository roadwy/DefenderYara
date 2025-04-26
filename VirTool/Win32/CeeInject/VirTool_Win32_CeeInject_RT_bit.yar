
rule VirTool_Win32_CeeInject_RT_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {30 01 69 c0 ?? ?? ?? ?? ff 4d 0c 05 ?? ?? ?? ?? 41 83 7d 0c 00 77 e9 } //1
		$a_03_1 = {8b 54 24 04 33 c0 eb ?? 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 } //1
		$a_03_2 = {88 45 08 8a 45 fe 8a c8 c0 f9 ?? c0 e0 ?? 02 45 ff 80 e1 ?? c0 e2 ?? 32 ca } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule VirTool_Win32_CeeInject_RT_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.RT!bit,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 8b 01 8b 40 0c 8b 40 0c 8b 00 } //1
		$a_01_1 = {8b 00 8b 40 18 89 45 f8 } //1
		$a_01_2 = {68 4d 12 1f 52 57 89 46 58 } //1
		$a_03_3 = {50 c7 45 e4 ?? ?? ?? ?? c7 45 e8 ?? ?? ?? ?? ff 56 48 89 45 fc } //1
		$a_03_4 = {8b c1 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 c6 ?? ?? ff 06 81 3e ?? ?? ?? ?? 75 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*5) >=9
 
}
rule VirTool_Win32_CeeInject_RT_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.RT!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 14 00 00 "
		
	strings :
		$a_01_0 = {54 68 61 74 20 70 6c 75 6d 62 65 72 20 6c 65 6e 74 20 68 65 72 20 61 20 6c 6f 74 20 6f 66 20 6d 6f 6e 65 79 } //1 That plumber lent her a lot of money
		$a_01_1 = {4a 6f 65 20 73 74 72 75 63 6b 20 68 69 6d 20 61 20 68 65 61 76 79 20 62 6c 6f 77 } //1 Joe struck him a heavy blow
		$a_01_2 = {54 68 61 74 20 67 75 61 72 64 20 73 6f 6c 64 20 68 69 6d 20 61 20 74 69 63 6b 65 74 } //1 That guard sold him a ticket
		$a_01_3 = {54 68 61 74 20 6a 6f 75 72 6e 61 6c 69 73 74 20 73 68 6f 77 65 64 20 74 68 65 6d 20 61 20 70 68 6f 74 6f 67 72 61 70 68 } //1 That journalist showed them a photograph
		$a_01_4 = {54 68 61 74 20 63 61 72 70 65 6e 74 65 72 20 73 74 72 75 63 6b 20 68 69 6d 20 61 20 68 65 61 76 79 20 62 6c 6f 77 } //1 That carpenter struck him a heavy blow
		$a_01_5 = {4c 65 73 74 65 72 73 20 65 78 2d 77 69 66 65 20 6f 72 64 65 72 73 20 68 65 72 20 61 20 6e 65 77 20 68 61 74 } //1 Lesters ex-wife orders her a new hat
		$a_01_6 = {57 69 6c 6c 69 65 20 62 6f 75 67 68 74 20 68 65 72 20 61 20 67 69 66 74 20 4a 61 63 6b 69 65 20 73 74 72 69 6b 65 73 20 68 69 6d 20 61 20 68 65 61 76 79 20 62 6c 6f 77 } //1 Willie bought her a gift Jackie strikes him a heavy blow
		$a_01_7 = {53 74 65 70 68 65 6e 20 73 74 72 75 63 6b 20 68 69 6d 20 61 20 68 65 61 76 79 20 62 6c 6f 77 } //1 Stephen struck him a heavy blow
		$a_01_8 = {54 68 6f 73 65 20 70 6f 6c 69 63 65 20 6f 66 66 69 63 65 72 73 20 6f 66 66 65 72 65 64 20 68 65 72 20 61 20 72 69 64 65 20 68 6f 6d 65 } //1 Those police officers offered her a ride home
		$a_01_9 = {54 68 61 74 20 73 74 75 64 65 6e 74 20 73 61 76 65 64 20 68 65 72 20 61 20 73 65 61 74 20 42 65 74 74 79 20 67 69 76 65 73 20 68 69 6d 20 61 20 6d 61 67 61 7a 69 6e 65 } //1 That student saved her a seat Betty gives him a magazine
		$a_01_10 = {45 64 20 6f 72 64 65 72 65 64 20 68 65 72 20 61 20 6e 65 77 20 64 72 65 73 73 20 41 62 72 61 68 61 6d 20 67 69 76 65 73 20 68 69 6d 20 61 20 6d 61 67 61 7a 69 6e 65 } //1 Ed ordered her a new dress Abraham gives him a magazine
		$a_01_11 = {54 68 6f 73 65 20 73 63 69 65 6e 74 69 73 74 73 20 74 6f 6c 64 20 68 65 72 20 74 68 65 20 73 68 6f 72 74 65 73 74 20 77 61 79 } //1 Those scientists told her the shortest way
		$a_01_12 = {4d 69 73 73 20 4a 6f 68 6e 73 6f 6e 20 65 6e 76 69 65 64 20 68 69 6d 20 68 69 73 20 67 6f 6f 64 20 66 6f 72 74 75 6e 65 20 54 68 61 74 20 6a 61 6e 69 74 6f 72 20 73 68 6f 77 73 20 74 68 65 6d 20 61 20 70 69 63 74 75 72 65 } //1 Miss Johnson envied him his good fortune That janitor shows them a picture
		$a_01_13 = {41 62 72 61 68 61 6d 20 62 72 6f 75 67 68 74 20 68 65 72 20 61 20 73 6d 61 6c 6c 20 70 72 65 73 65 6e 74 20 44 65 62 62 69 65 20 74 61 75 67 68 74 20 74 68 65 6d 20 45 6e 67 6c 69 73 68 } //1 Abraham brought her a small present Debbie taught them English
		$a_01_14 = {4e 65 64 20 73 65 6e 64 73 20 68 69 6d 20 61 20 70 61 63 6b 61 67 65 20 54 68 6f 73 65 20 74 61 78 69 20 64 72 69 76 65 72 73 20 6d 61 6b 65 20 68 69 6d 20 73 6f 6d 65 20 63 6f 66 66 65 65 } //1 Ned sends him a package Those taxi drivers make him some coffee
		$a_01_15 = {54 68 61 74 20 6d 61 6e 61 67 65 72 20 72 65 61 64 20 74 68 65 20 63 68 69 6c 64 72 65 6e 20 61 20 73 74 6f 72 79 } //1 That manager read the children a story
		$a_01_16 = {54 68 61 74 20 74 65 61 63 68 65 72 20 77 72 6f 74 65 20 68 65 72 20 61 20 6c 65 74 74 65 72 } //1 That teacher wrote her a letter
		$a_01_17 = {41 6c 62 65 72 74 20 6c 65 6e 64 73 20 68 69 6d 20 61 20 70 65 6e 63 69 6c } //1 Albert lends him a pencil
		$a_01_18 = {41 6e 6e 20 4c 79 6e 6e 20 73 65 6e 74 20 68 69 6d 20 61 20 70 61 63 6b 61 67 65 20 57 69 6c 6c 69 65 20 62 6f 75 67 68 74 20 68 65 72 20 61 20 67 69 66 74 } //1 Ann Lynn sent him a package Willie bought her a gift
		$a_01_19 = {4a 6f 61 6e 6e 65 73 20 6d 6f 74 68 65 72 20 6f 66 66 65 72 73 20 68 65 72 20 61 20 62 72 69 62 65 20 54 68 6f 73 65 20 73 63 69 65 6e 63 65 20 74 65 61 63 68 65 72 73 20 62 75 79 20 68 65 72 20 61 20 67 69 66 74 } //1 Joannes mother offers her a bribe Those science teachers buy her a gift
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=2
 
}