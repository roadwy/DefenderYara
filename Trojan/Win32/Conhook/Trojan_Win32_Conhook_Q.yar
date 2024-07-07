
rule Trojan_Win32_Conhook_Q{
	meta:
		description = "Trojan:Win32/Conhook.Q,SIGNATURE_TYPE_PEHSTR_EXT,ffffff97 00 ffffff97 00 09 00 00 "
		
	strings :
		$a_02_0 = {2f 72 65 64 69 72 65 63 74 2f 90 02 03 2e 70 68 70 90 00 } //100
		$a_02_1 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 90 03 04 07 6a 75 61 6e 6d 73 20 6a 75 61 6e 90 00 } //50
		$a_00_2 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 6a 75 61 6e } //50 software\microsoft\juan
		$a_00_3 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 61 66 25 30 38 78 } //50 software\microsoft\af%08x
		$a_00_4 = {73 75 70 65 72 6a 75 61 6e } //1 superjuan
		$a_00_5 = {54 72 61 63 6b 44 4a 75 61 6e } //1 TrackDJuan
		$a_00_6 = {4a 75 61 6e 5f 34 30 34 } //1 Juan_404
		$a_00_7 = {6a 6e 5f 74 72 5f 25 30 38 78 } //1 jn_tr_%08x
		$a_00_8 = {6a 75 61 6e 5f 74 72 61 63 6b } //1 juan_track
	condition:
		((#a_02_0  & 1)*100+(#a_02_1  & 1)*50+(#a_00_2  & 1)*50+(#a_00_3  & 1)*50+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=151
 
}