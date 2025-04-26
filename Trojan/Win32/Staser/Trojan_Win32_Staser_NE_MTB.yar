
rule Trojan_Win32_Staser_NE_MTB{
	meta:
		description = "Trojan:Win32/Staser.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {73 67 67 6b 6d 6e 6e 6f 70 70 71 71 72 72 73 73 75 } //5 sggkmnnoppqqrrssu
		$a_01_1 = {73 72 6c 69 6c 6f 71 74 76 75 } //5 srliloqtvu
		$a_01_2 = {79 6b 67 68 6a 6b 6b 6b 6e 72 75 7a } //5 ykghjkkknruz
		$a_01_3 = {4c 64 72 52 65 67 69 73 74 65 72 44 6c 6c 4e 6f 74 69 66 69 63 61 74 69 6f } //4 LdrRegisterDllNotificatio
		$a_01_4 = {41 70 69 53 65 74 51 75 65 72 79 41 70 69 53 65 74 50 72 65 73 65 6e 63 65 } //4 ApiSetQueryApiSetPresence
		$a_01_5 = {53 75 62 33 44 69 73 6b 4f 70 65 6e 41 } //4 Sub3DiskOpenA
		$a_01_6 = {52 65 67 69 73 74 65 72 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 41 } //4 RegisterClipboardFormatA
		$a_01_7 = {53 4d 54 50 46 72 6f 6d 4e 4c } //3 SMTPFromNL
		$a_01_8 = {66 69 63 61 74 69 6f 6e } //3 fication
		$a_01_9 = {47 65 74 44 43 45 78 } //3 GetDCEx
		$a_01_10 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //2 GetClipboardData
		$a_01_11 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //2 GetTickCount
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4+(#a_01_6  & 1)*4+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3+(#a_01_9  & 1)*3+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2) >=44
 
}