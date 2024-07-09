
rule Trojan_Win32_SuspLolbinLaunch_B_rundll{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.B!rundll,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 [0-40] 6d 00 73 00 68 00 74 00 6d 00 6c 00 } //1
		$a_00_1 = {5c 00 66 00 69 00 6c 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //-5 \filter.exe
		$a_00_2 = {74 00 68 00 6f 00 72 00 5c 00 73 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65 00 73 00 } //-5 thor\signatures
		$a_00_3 = {2e 00 79 00 6d 00 73 00 2d 00 74 00 65 00 78 00 74 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //-5 .yms-textfilter
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*-5+(#a_00_2  & 1)*-5+(#a_00_3  & 1)*-5) >=1
 
}