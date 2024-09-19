
rule Trojan_MacOS_SuspInfostealer_X{
	meta:
		description = "Trojan:MacOS/SuspInfostealer.X,SIGNATURE_TYPE_MACHOHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 54 52 41 54 4f 46 45 41 52 } //6 STRATOFEAR
		$a_00_1 = {2f 4c 69 62 72 61 72 79 2f 46 6f 6e 74 73 2f 41 70 70 6c 65 53 44 47 6f 74 68 69 63 4e 65 6f } //1 /Library/Fonts/AppleSDGothicNeo
		$a_00_2 = {62 61 73 69 63 5f 73 74 72 69 6e 67 2f 4c 69 62 72 61 72 79 2f 46 6f 6e 74 73 2f 70 69 6e 67 66 61 6e 67 } //1 basic_string/Library/Fonts/pingfang
		$a_00_3 = {2f 75 73 72 2f 73 62 69 6e 2f 73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 53 50 48 61 72 64 77 61 72 65 44 61 74 61 54 79 70 65 } //1 /usr/sbin/system_profiler SPHardwareDataType
		$a_00_4 = {2f 75 73 72 2f 62 69 6e 2f 73 77 5f 76 65 72 73 } //1 /usr/bin/sw_vers
		$a_00_5 = {64 73 63 6c 20 2e 20 2d 6c 69 73 74 20 2f 55 73 65 72 73 20 7c 20 67 72 65 70 20 2d 76 20 27 5e 5f 27 } //1 dscl . -list /Users | grep -v '^_'
		$a_00_6 = {44 6f 6d 61 69 6e 3a 20 00 4d 6f 6e 69 74 6f 72 69 6e 67 20 44 65 76 69 63 65 20 4d 6f 75 6e 74 73 3a 20 00 2f 56 6f 6c 75 6d 65 73 } //1
	condition:
		((#a_00_0  & 1)*6+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=9
 
}