
rule Trojan_Win32_Dialsnif_gen_C{
	meta:
		description = "Trojan:Win32/Dialsnif.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,3b 00 31 00 3a 00 00 "
		
	strings :
		$a_00_0 = {5c 63 6c 6f 73 65 2e 6c 6f 67 } //1 \close.log
		$a_00_1 = {5c 64 69 61 6c 2e 6c 6f 67 } //1 \dial.log
		$a_00_2 = {5c 53 68 65 6c 6c 5c 4f 70 65 6e } //1 \Shell\Open
		$a_00_3 = {5c 53 68 65 6c 6c 5c 4f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 } //1 \Shell\Open\Command
		$a_00_4 = {5c 57 69 6e 49 6e 69 74 2e 49 6e 69 } //1 \WinInit.Ini
		$a_00_5 = {44 53 42 45 41 47 4c 45 2d 31 31 31 31 2d 31 31 31 31 2d 31 31 31 31 2d 31 31 31 31 31 31 31 31 31 31 31 31 } //1 DSBEAGLE-1111-1111-1111-111111111111
		$a_00_6 = {43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c } //1 Control Panel\International
		$a_00_7 = {44 65 66 61 75 6c 74 49 6e 74 65 72 6e 65 74 } //1 DefaultInternet
		$a_00_8 = {74 72 61 63 6b 6b 65 79 2e 65 78 65 } //1 trackkey.exe
		$a_00_9 = {74 72 61 63 6b 75 72 6c 2e 65 78 65 } //1 trackurl.exe
		$a_00_10 = {6b 69 6c 6c 2e 65 78 65 } //1 kill.exe
		$a_00_11 = {64 69 61 6c 2e 65 78 65 } //1 dial.exe
		$a_00_12 = {64 69 61 6c 3a 2f 2f } //1 dial://
		$a_00_13 = {64 69 72 65 63 74 2e 65 78 65 } //1 direct.exe
		$a_00_14 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 64 73 65 72 76 65 72 2e 63 6f 6d } //1 http://www.adserver.com
		$a_00_15 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6c 65 78 61 2e 63 6f 6d } //1 http://www.alexa.com
		$a_00_16 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6c 69 62 61 62 61 2e 63 6f 6d } //1 http://www.alibaba.com
		$a_00_17 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6d 61 7a 6f 6e 2e 63 6f 6d } //1 http://www.amazon.com
		$a_00_18 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 70 70 6c 65 2e 63 6f 6d } //1 http://www.apple.com
		$a_00_19 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6e 6e 2e 63 6f 6d } //1 http://www.cnn.com
		$a_00_20 = {68 74 74 70 3a 2f 2f 77 77 77 2e 65 62 61 79 2e 63 6f 6d } //1 http://www.ebay.com
		$a_00_21 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 61 73 74 63 6c 69 63 6b 2e 63 6f 6d } //1 http://www.fastclick.com
		$a_00_22 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 63 71 2e 63 6f 6d } //1 http://www.icq.com
		$a_00_23 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 79 63 6f 73 2e 63 6f 6d } //1 http://www.lycos.com
		$a_00_24 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 61 70 71 75 65 73 74 2e 63 6f 6d } //1 http://www.mapquest.com
		$a_00_25 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //1 http://www.microsoft.com
		$a_00_26 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 6c 62 2e 63 6f 6d } //1 http://www.mlb.com
		$a_00_27 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 6f 6e 73 74 65 72 2e 63 6f 6d } //1 http://www.monster.com
		$a_00_28 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 62 61 2e 63 6f 6d } //1 http://www.nba.com
		$a_00_29 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 65 74 73 63 61 70 65 2e 63 6f 6d } //1 http://www.netscape.com
		$a_00_30 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 79 74 69 6d 65 73 2e 63 6f 6d } //1 http://www.nytimes.com
		$a_00_31 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 72 69 70 6f 64 2e 63 6f 6d } //1 http://www.tripod.com
		$a_00_32 = {68 74 74 70 3a 2f 2f 77 77 77 2e 78 61 6e 67 61 2e 63 6f 6d } //1 http://www.xanga.com
		$a_00_33 = {68 74 74 70 3a 2f 2f 77 77 77 2e 79 61 68 6f 6f 2e 63 6f 6d } //1 http://www.yahoo.com
		$a_00_34 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 } //1 Software\Microsoft\Internet Account Manager
		$a_00_35 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 5c } //1 Software\Microsoft\Internet Account Manager\Accounts\
		$a_00_36 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //1 Software\Microsoft\Internet Explorer
		$a_00_37 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 52 41 53 20 41 75 74 6f 44 69 61 6c 5c 44 65 66 61 75 6c 74 } //1 Software\Microsoft\RAS AutoDial\Default
		$a_00_38 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 Software\Microsoft\Windows\CurrentVersion
		$a_00_39 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 55 73 65 72 20 41 67 65 6e 74 5c 50 6f 73 74 20 50 6c 61 74 66 6f 72 6d } //1 Software\Microsoft\Windows\CurrentVersion\Internet Settings\User Agent\Post Platform
		$a_00_40 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_41 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 53 65 72 76 69 63 65 73 } //1 Software\Microsoft\Windows\CurrentVersion\RunServices
		$a_00_42 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 Software\Microsoft\WinNT\CurrentVersion
		$a_01_43 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_01_44 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_45 = {45 6e 75 6d 50 72 6f 63 65 73 73 65 73 } //1 EnumProcesses
		$a_00_46 = {45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73 } //1 EnumProcessModules
		$a_00_47 = {4d 6f 64 75 6c 65 33 32 46 69 72 73 74 } //1 Module32First
		$a_00_48 = {4d 6f 64 75 6c 65 33 32 4e 65 78 74 } //1 Module32Next
		$a_00_49 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_00_50 = {52 61 73 45 6e 75 6d 44 65 76 69 63 65 73 41 } //1 RasEnumDevicesA
		$a_00_51 = {52 61 73 47 65 74 45 6e 74 72 79 44 69 61 6c 50 61 72 61 6d 73 41 } //1 RasGetEntryDialParamsA
		$a_00_52 = {52 61 73 47 65 74 45 6e 74 72 79 50 72 6f 70 65 72 74 69 65 73 41 } //1 RasGetEntryPropertiesA
		$a_00_53 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 } //1 RegisterServiceProcess
		$a_00_54 = {52 65 6d 6f 76 65 44 69 72 65 63 74 6f 72 79 41 } //1 RemoveDirectoryA
		$a_00_55 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_00_56 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_00_57 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //1 TerminateProcess
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1+(#a_00_19  & 1)*1+(#a_00_20  & 1)*1+(#a_00_21  & 1)*1+(#a_00_22  & 1)*1+(#a_00_23  & 1)*1+(#a_00_24  & 1)*1+(#a_00_25  & 1)*1+(#a_00_26  & 1)*1+(#a_00_27  & 1)*1+(#a_00_28  & 1)*1+(#a_00_29  & 1)*1+(#a_00_30  & 1)*1+(#a_00_31  & 1)*1+(#a_00_32  & 1)*1+(#a_00_33  & 1)*1+(#a_00_34  & 1)*1+(#a_00_35  & 1)*1+(#a_00_36  & 1)*1+(#a_00_37  & 1)*1+(#a_00_38  & 1)*1+(#a_00_39  & 1)*1+(#a_00_40  & 1)*1+(#a_00_41  & 1)*1+(#a_00_42  & 1)*1+(#a_01_43  & 1)*1+(#a_01_44  & 1)*1+(#a_00_45  & 1)*1+(#a_00_46  & 1)*1+(#a_00_47  & 1)*1+(#a_00_48  & 1)*1+(#a_00_49  & 1)*1+(#a_00_50  & 1)*1+(#a_00_51  & 1)*1+(#a_00_52  & 1)*1+(#a_00_53  & 1)*1+(#a_00_54  & 1)*1+(#a_00_55  & 1)*1+(#a_00_56  & 1)*1+(#a_00_57  & 1)*1) >=49
 
}