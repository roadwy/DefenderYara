
rule Trojan_Win32_Virtumonde{
	meta:
		description = "Trojan:Win32/Virtumonde,SIGNATURE_TYPE_PEHSTR_EXT,36 00 36 00 0f 00 00 "
		
	strings :
		$a_00_0 = {57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c } //10 Windows NT\CurrentVersion\Winlogon\Notify\
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_2 = {50 65 6e 64 69 6e 67 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 } //10 PendingFileRenameOperations
		$a_01_3 = {41 73 79 6e 63 68 72 6f 6e 6f 75 73 } //10 Asynchronous
		$a_01_4 = {2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00 4f 66 66 45 76 65 6e 74 00 4f 6e 45 76 65 6e 74 00 51 75 65 72 79 53 74 61 72 74 53 65 71 75 65 6e 63 65 } //5 搮汬䤀獮慴汬伀晦癅湥t湏癅湥t畑牥卹慴瑲敓畱湥散
		$a_00_5 = {53 65 74 56 4d 00 53 79 73 4c 6f 67 6f 66 66 00 53 79 73 4c 6f 67 6f 6e } //5 敓噴M祓䱳杯景f祓䱳杯湯
		$a_00_6 = {25 30 38 78 5f 5f 5f 31 32 32 00 00 } //5
		$a_00_7 = {69 6e 73 6d 75 74 61 6e 68 6f 6b 75 65 65 72 67 73 64 6c 64 73 } //1 insmutanhokueergsdlds
		$a_00_8 = {62 75 73 68 5f 73 73 65 76 65 6e 74 } //1 bush_ssevent
		$a_00_9 = {6b 6c 69 6e 74 6f 6e 5f 73 73 6d 6d 66 } //1 klinton_ssmmf
		$a_01_10 = {42 50 43 72 75 73 68 } //1 BPCrush
		$a_00_11 = {41 4e 54 49 53 50 59 57 41 52 45 3f 47 43 41 53 53 45 52 56 41 4c 45 52 54 2e 45 58 45 } //1 ANTISPYWARE?GCASSERVALERT.EXE
		$a_01_12 = {50 6f 70 75 70 73 53 68 6f 77 6e 3d 25 69 3b 4d 61 78 50 6f 70 75 70 50 65 72 44 61 79 3d 25 69 } //1 PopupsShown=%i;MaxPopupPerDay=%i
		$a_01_13 = {53 79 73 50 72 6f 74 65 63 74 5c 41 63 74 69 76 61 74 69 6f 6e 43 6f 64 65 } //1 SysProtect\ActivationCode
		$a_01_14 = {57 69 6e 53 6f 66 74 77 61 72 65 5c 57 69 6e 61 6e 74 69 76 69 72 75 73 20 32 30 30 35 5c 41 63 74 69 76 61 74 69 6f 6e 43 6f 64 65 } //1 WinSoftware\Winantivirus 2005\ActivationCode
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*5+(#a_00_5  & 1)*5+(#a_00_6  & 1)*5+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1+(#a_00_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=54
 
}