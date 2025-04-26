
rule Backdoor_Win32_CarpeDiem{
	meta:
		description = "Backdoor:Win32/CarpeDiem,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 61 73 44 69 61 6c 45 76 65 6e 74 } //1 RasDialEvent
		$a_01_1 = {43 44 55 70 64 61 74 65 72 2e 65 78 65 } //3 CDUpdater.exe
		$a_01_2 = {43 3a 5c 4d 6f 6e 74 6f 72 67 75 65 69 6c 5c } //2 C:\Montorgueil\
		$a_01_3 = {68 74 74 70 3a 2f 2f 64 69 61 6c 75 70 2e 63 61 72 70 65 64 69 65 6d 2e 66 72 2f 70 65 72 6c 2f 64 69 61 6c 75 70 2e 70 6c } //5 http://dialup.carpediem.fr/perl/dialup.pl
		$a_01_4 = {68 74 74 70 3a 2f 2f 64 69 61 6c 75 70 2e 63 61 72 70 65 64 69 65 6d 2e 66 72 2f 70 65 72 6c 2f 63 6f 75 6e 74 64 69 61 6c 75 70 69 6e 74 65 72 2e 70 6c 3f } //5 http://dialup.carpediem.fr/perl/countdialupinter.pl?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=16
 
}
rule Backdoor_Win32_CarpeDiem_2{
	meta:
		description = "Backdoor:Win32/CarpeDiem,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 69 44 69 61 6c 4d 6f 64 65 6d 47 65 74 50 69 6e 67 45 76 65 6e 74 } //3 uiDialModemGetPingEvent
		$a_01_1 = {64 69 61 6c 75 70 2e 70 6c } //2 dialup.pl
		$a_01_2 = {68 74 74 70 3a 2f 2f 64 69 61 6c 75 70 2e 63 61 72 70 65 64 69 65 6d 2e 66 72 2f 70 65 72 6c 2f 63 6f 75 6e 74 64 69 61 6c 75 70 69 6e 74 65 72 2e 70 6c 3f } //5 http://dialup.carpediem.fr/perl/countdialupinter.pl?
		$a_01_3 = {68 74 74 70 3a 2f 2f 61 64 73 6c 2e 63 61 72 70 65 64 69 65 6d 2e 66 72 2f 70 65 72 6c 2f 69 6e 76 6f 63 5f 6f 6e 65 77 61 79 2e 70 6c 3f } //5 http://adsl.carpediem.fr/perl/invoc_oneway.pl?
		$a_01_4 = {43 44 5f 44 69 61 6c 65 72 } //2 CD_Dialer
		$a_01_5 = {43 44 55 70 64 61 74 65 72 2e 65 78 65 } //2 CDUpdater.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=14
 
}
rule Backdoor_Win32_CarpeDiem_3{
	meta:
		description = "Backdoor:Win32/CarpeDiem,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 70 77 61 74 63 68 77 69 6e 73 68 6f 65 6e 6f 6c 6f 67 } //1 ipwatchwinshoenolog
		$a_01_1 = {53 6f 66 74 57 61 72 65 5c 43 61 72 70 65 44 69 65 6d 56 61 72 73 5c 4b 69 74 5c } //1 SoftWare\CarpeDiemVars\Kit\
		$a_01_2 = {64 69 61 6c 75 70 2e 63 61 72 70 65 64 69 65 6d 2e } //1 dialup.carpediem.
		$a_01_3 = {70 65 72 6c 2f 63 6f 75 6e 74 64 69 61 6c 75 70 69 6e 74 65 72 2e 70 6c 3f 6e 61 6d 65 3d } //1 perl/countdialupinter.pl?name=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}