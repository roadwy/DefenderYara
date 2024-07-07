
rule Trojan_Win32_Ninunarch_K{
	meta:
		description = "Trojan:Win32/Ninunarch.K,SIGNATURE_TYPE_PEHSTR,6f 00 6f 00 04 00 00 "
		
	strings :
		$a_01_0 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72 } //100 㜷⌧ጝ㤤潮煰牲牲牲瑳杞幵甤敨牴牲牲
		$a_01_1 = {64 31 6f 32 6f 33 68 34 6b 35 74 36 74 37 6d 38 63 39 75 30 70 31 6b 32 69 33 75 34 74 } //10 d1o2o3h4k5t6t7m8c9u0p1k2i3u4t
		$a_01_2 = {6c 61 62 65 6c 52 65 74 72 79 53 65 6e 64 53 4d 53 } //1 labelRetrySendSMS
		$a_01_3 = {51 46 74 70 44 54 50 } //1 QFtpDTP
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=111
 
}