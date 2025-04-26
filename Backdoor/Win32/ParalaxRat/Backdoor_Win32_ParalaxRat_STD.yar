
rule Backdoor_Win32_ParalaxRat_STD{
	meta:
		description = "Backdoor:Win32/ParalaxRat.STD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 63 6f 46 47 2f 47 37 72 32 6b 34 } //1 /coFG/G7r2k4
		$a_01_1 = {34 44 35 41 36 42 36 35 37 32 36 45 36 35 36 43 33 33 33 32 30 30 30 30 35 30 34 35 } //1 4D5A6B65726E656C333200005045
		$a_01_2 = {3c 62 6c 6f 63 6b 32 3e 30 3c 2f 62 6c 6f 63 6b 32 3e } //1 <block2>0</block2>
		$a_01_3 = {78 6d 72 5f 6d 69 6e 65 5f 73 74 6f 70 } //1 xmr_mine_stop
		$a_01_4 = {72 65 6d 6f 74 65 62 72 6f 77 73 65 72 5f 69 6e 66 6f } //1 remotebrowser_info
		$a_01_5 = {4b 45 59 4c 4f 47 3a 20 } //1 KEYLOG: 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule Backdoor_Win32_ParalaxRat_STD_2{
	meta:
		description = "Backdoor:Win32/ParalaxRat.STD,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_01_0 = {2f 63 6f 46 47 2f 47 37 72 32 6b 34 } //1 /coFG/G7r2k4
		$a_01_1 = {73 70 6d 32 31 2e 6e 65 74 } //1 spm21.net
		$a_01_2 = {78 6d 72 5f 6d 69 6e 65 5f 73 74 6f 70 } //1 xmr_mine_stop
		$a_01_3 = {68 76 6e 63 5f 73 74 61 72 74 } //1 hvnc_start
		$a_01_4 = {6b 6c 67 6f 6e 6c 69 6e 65 73 74 61 72 74 } //1 klgonlinestart
		$a_01_5 = {73 68 65 6c 6c 5f 65 78 65 63 } //1 shell_exec
		$a_01_6 = {73 63 72 65 65 6e 6c 69 76 65 5f 73 74 6f 70 } //1 screenlive_stop
		$a_01_7 = {72 65 6d 6f 74 65 62 72 6f 77 73 65 72 } //1 remotebrowser
		$a_01_8 = {75 61 63 5f 62 79 70 61 73 73 } //1 uac_bypass
		$a_01_9 = {75 73 62 5f 73 70 72 65 61 64 } //1 usb_spread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=7
 
}