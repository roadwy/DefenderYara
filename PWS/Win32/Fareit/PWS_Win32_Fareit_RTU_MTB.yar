
rule PWS_Win32_Fareit_RTU_MTB{
	meta:
		description = "PWS:Win32/Fareit.RTU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 6b 64 6f 67 61 6e 65 76 64 65 6e 65 76 65 2e 6e 65 74 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 50 61 6e 65 6c 2f 67 61 74 65 2e 70 68 70 } //10 http://akdoganevdeneve.net/wp-content/Panel/gate.php
		$a_01_1 = {59 55 49 50 57 44 46 49 4c 45 30 59 55 49 50 4b 44 46 49 4c 45 30 59 55 49 43 52 59 50 54 45 44 30 59 55 49 31 2e 30 } //10 YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0
		$a_01_2 = {4f 67 75 71 63 6f 67 74 6b 65 63 } //10 Oguqcogtkec
		$a_01_3 = {47 65 74 4e 61 74 69 76 65 53 79 73 74 65 6d 49 6e 66 6f } //1 GetNativeSystemInfo
		$a_01_4 = {6f 75 74 6c 6f 6f 6b 20 61 63 63 6f 75 6e 74 20 6d 61 6e 61 67 65 72 20 70 61 73 73 77 6f 72 64 73 } //1 outlook account manager passwords
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}