
rule Trojan_Win64_IcedID_MV_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 6b 76 62 77 6d 68 71 7a 65 6d 70 79 65 65 6a } //2 akvbwmhqzempyeej
		$a_01_1 = {61 6c 73 77 64 7a 72 6f 77 6d 71 6c 6c 76 62 71 } //2 alswdzrowmqllvbq
		$a_01_2 = {63 61 6b 75 69 7a 75 7a 65 78 76 61 } //2 cakuizuzexva
		$a_01_3 = {68 78 78 78 78 78 79 6c 76 6b 74 6c 64 79 } //2 hxxxxxylvktldy
		$a_01_4 = {47 65 74 43 61 70 74 75 72 65 } //1 GetCapture
		$a_01_5 = {49 6e 69 74 4e 65 74 77 6f 72 6b 41 64 64 72 65 73 73 43 6f 6e 74 72 6f 6c } //1 InitNetworkAddressControl
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}
rule Trojan_Win64_IcedID_MV_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0b 00 00 "
		
	strings :
		$a_01_0 = {4b 48 67 79 74 55 2e 64 6c 6c } //10 KHgytU.dll
		$a_01_1 = {68 6d 70 53 67 53 2e 64 6c 6c } //10 hmpSgS.dll
		$a_01_2 = {50 6c 75 67 69 6e 49 6e 69 74 } //5 PluginInit
		$a_01_3 = {43 6e 76 44 76 68 } //1 CnvDvh
		$a_01_4 = {4d 41 53 30 77 58 36 30 54 44 36 } //1 MAS0wX60TD6
		$a_01_5 = {59 77 49 6a 72 47 70 73 70 } //1 YwIjrGpsp
		$a_01_6 = {62 56 4e 70 74 4a 4d 4b 76 } //1 bVNptJMKv
		$a_01_7 = {47 73 49 7a 4d 31 } //1 GsIzM1
		$a_01_8 = {4c 39 6a 62 62 6e 36 75 54 31 55 } //1 L9jbbn6uT1U
		$a_01_9 = {69 47 7a 69 52 51 73 50 } //1 iGziRQsP
		$a_01_10 = {72 49 4a 6c 41 63 6b } //1 rIJlAck
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=19
 
}
rule Trojan_Win64_IcedID_MV_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 "
		
	strings :
		$a_01_0 = {67 68 75 61 73 69 66 6d 69 6a 6f 61 73 68 75 64 61 64 6a 6b 61 73 69 64 6a 61 73 64 75 68 69 } //10 ghuasifmijoashudadjkasidjasduhi
		$a_01_1 = {79 75 69 73 61 66 6d 6b 6c 61 6a 69 73 68 75 64 66 62 68 61 6a 6b 68 64 75 73 67 79 68 6a 73 61 } //10 yuisafmklajishudfbhajkhdusgyhjsa
		$a_03_2 = {22 20 0b 02 90 01 02 00 16 00 00 00 0e 03 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 90 00 } //5
		$a_01_3 = {44 75 70 6c 69 63 61 74 65 48 61 6e 64 6c 65 } //2 DuplicateHandle
		$a_01_4 = {57 61 69 74 46 6f 72 4d 75 6c 74 69 70 6c 65 4f 62 6a 65 63 74 73 45 78 } //2 WaitForMultipleObjectsEx
		$a_01_5 = {43 72 65 61 74 65 45 76 65 6e 74 57 } //2 CreateEventW
		$a_01_6 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //2 OpenProcess
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*5+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=23
 
}