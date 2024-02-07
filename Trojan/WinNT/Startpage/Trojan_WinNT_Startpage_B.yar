
rule Trojan_WinNT_Startpage_B{
	meta:
		description = "Trojan:WinNT/Startpage.B,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 32 37 2e 30 2e 30 2e 31 20 20 73 63 61 6e 2e 6b 69 6e 67 73 6f 66 74 2e 63 6f 6d } //01 00  127.0.0.1  scan.kingsoft.com
		$a_01_1 = {31 32 37 2e 30 2e 30 2e 31 20 20 75 70 64 61 74 65 2e 72 69 73 69 6e 67 2e 63 6f 6d 2e 63 6e } //01 00  127.0.0.1  update.rising.com.cn
		$a_01_2 = {31 32 37 2e 30 2e 30 2e 31 20 20 64 6f 77 6e 6c 6f 61 64 2e 72 69 73 69 6e 67 2e 63 6f 6d 2e 63 6e } //01 00  127.0.0.1  download.rising.com.cn
		$a_01_3 = {2e 6b 61 73 70 65 72 73 6b 79 2d 6c 61 62 73 2e 63 6f 6d } //01 00  .kaspersky-labs.com
		$a_01_4 = {50 73 43 72 65 61 74 65 53 79 73 74 65 6d 54 68 72 65 61 64 } //01 00  PsCreateSystemThread
		$a_01_5 = {50 73 4c 6f 6f 6b 75 70 50 72 6f 63 65 73 73 42 79 50 72 6f 63 65 73 73 49 64 } //01 00  PsLookupProcessByProcessId
		$a_01_6 = {4f 62 52 65 66 65 72 65 6e 63 65 4f 62 6a 65 63 74 42 79 48 61 6e 64 6c 65 } //01 00  ObReferenceObjectByHandle
		$a_01_7 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_01_8 = {50 73 53 65 74 43 72 65 61 74 65 50 72 6f 63 65 73 73 4e 6f 74 69 66 79 52 6f 75 74 69 6e 65 } //01 00  PsSetCreateProcessNotifyRoutine
		$a_01_9 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //01 00  ntoskrnl.exe
		$a_01_10 = {53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00 } //01 00  Start Page
		$a_01_11 = {5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 4d 00 61 00 69 00 6e 00 } //01 00  \Software\Microsoft\Internet Explorer\Main
		$a_00_12 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //01 00  \SystemRoot\system32\drivers\etc\hosts
		$a_01_13 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 53 00 79 00 73 00 74 00 65 00 6d 00 58 00 } //01 00  \DosDevices\LocalSystemX
		$a_01_14 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 53 00 79 00 73 00 74 00 65 00 6d 00 58 00 } //00 00  \Device\LocalSystemX
	condition:
		any of ($a_*)
 
}