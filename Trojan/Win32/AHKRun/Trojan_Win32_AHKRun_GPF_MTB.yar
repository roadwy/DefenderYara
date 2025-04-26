
rule Trojan_Win32_AHKRun_GPF_MTB{
	meta:
		description = "Trojan:Win32/AHKRun.GPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 74 72 52 65 70 6c 61 63 65 28 76 61 6c 75 65 } //1 StrReplace(value
		$a_01_1 = {52 65 67 45 78 4d 61 74 63 68 28 74 65 78 74 } //1 RegExMatch(text
		$a_01_2 = {41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //1 AntiVirusProduct
		$a_01_3 = {41 6e 74 69 53 70 79 77 61 72 65 50 72 6f 64 75 63 74 } //1 AntiSpywareProduct
		$a_01_4 = {72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 32 } //1 root\SecurityCenter2
		$a_01_5 = {41 5f 41 70 70 44 61 74 61 } //1 A_AppData
		$a_01_6 = {55 32 39 6d 64 48 64 68 63 6d 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 64 70 62 6d 52 76 64 33 4e 63 51 33 56 79 63 6d 56 75 64 46 5a 6c 63 6e 4e 70 62 32 35 63 55 6e 56 75 } //1 U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}