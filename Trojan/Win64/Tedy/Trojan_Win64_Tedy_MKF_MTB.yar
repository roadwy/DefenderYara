
rule Trojan_Win64_Tedy_MKF_MTB{
	meta:
		description = "Trojan:Win64/Tedy.MKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,35 00 35 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 61 63 63 65 73 73 4b 65 79 6e 61 6d 65 2e 64 6c 6c } //20 naccessKeyname.dll
		$a_01_1 = {55 73 65 72 2e 74 78 74 43 6c 69 70 62 6f 61 72 64 2e 74 78 74 50 72 6f 63 65 73 73 65 73 2e 74 78 74 50 49 44 } //15 User.txtClipboard.txtProcesses.txtPID
		$a_01_2 = {42 6f 6f 6b 6d 61 72 6b 73 2e 74 78 74 44 6f 77 6e 6c 6f 61 64 73 2e 74 78 74 } //10 Bookmarks.txtDownloads.txt
		$a_01_3 = {64 73 63 72 65 65 6e 73 68 6f 74 6c 6f 67 66 69 6c 65 } //5 dscreenshotlogfile
		$a_01_4 = {56 69 63 74 69 6d 3a 20 3c 63 6f 64 65 3e } //3 Victim: <code>
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*3) >=53
 
}