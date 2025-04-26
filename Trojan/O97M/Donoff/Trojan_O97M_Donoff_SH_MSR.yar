
rule Trojan_O97M_Donoff_SH_MSR{
	meta:
		description = "Trojan:O97M/Donoff.SH!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6f 70 65 6e 20 2d 61 20 53 61 66 61 72 69 } //1 open -a Safari
		$a_00_1 = {42 61 73 65 36 34 44 65 63 6f 64 65 28 4f 72 69 67 69 6e 61 6c 51 53 29 20 26 20 22 26 75 6e 61 6d 65 3d 22 20 26 20 55 52 4c 45 6e 63 6f 64 65 28 47 65 74 4d 61 63 68 69 6e 65 44 61 74 61 28 22 75 73 65 72 6e 61 6d 65 22 29 29 20 26 20 22 26 64 6e 61 6d 65 3d 22 20 26 20 55 52 4c 45 6e 63 6f 64 65 28 47 65 74 4d 61 63 68 69 6e 65 44 61 74 61 28 22 66 75 6c 6c 6e 61 6d 65 22 29 29 20 26 20 22 26 63 6e 61 6d 65 3d 22 20 26 20 55 52 4c 45 6e 63 6f 64 65 28 47 65 74 4d 61 63 68 69 6e 65 44 61 74 61 28 22 6d 61 63 68 69 6e 65 22 29 } //1 Base64Decode(OriginalQS) & "&uname=" & URLEncode(GetMachineData("username")) & "&dname=" & URLEncode(GetMachineData("fullname")) & "&cname=" & URLEncode(GetMachineData("machine")
		$a_03_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 28 [0-15] 2c 20 22 6e 65 74 22 2c 20 22 75 73 65 20 2a 20 22 20 26 20 55 52 4c 2c 20 22 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 22 2c 20 76 62 48 69 64 65 } //1
		$a_00_3 = {68 74 74 70 3a 2f 2f 4d 6f 74 6f 62 69 74 2e 63 7a } //1 http://Motobit.cz
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}