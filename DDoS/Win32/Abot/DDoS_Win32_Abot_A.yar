
rule DDoS_Win32_Abot_A{
	meta:
		description = "DDoS:Win32/Abot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {2f 67 61 74 65 2e 70 68 70 3f 68 77 69 64 3d } //01 00  /gate.php?hwid=
		$a_01_2 = {26 6c 6f 63 61 6c 69 70 3d } //01 00  &localip=
		$a_01_3 = {26 77 69 6e 76 65 72 3d } //9c ff  &winver=
		$a_00_4 = {4d 00 61 00 67 00 6e 00 65 00 74 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 41 00 72 00 74 00 69 00 66 00 61 00 63 00 74 00 73 00 2e 00 64 00 6c 00 6c 00 } //9c ff  Magnet.Content.Artifacts.dll
		$a_00_5 = {53 79 73 74 65 6d 2e 43 6f 6c 6c 65 63 74 69 6f 6e 73 2e 47 65 6e 65 72 69 63 2e 49 43 6f 6d 70 61 72 65 72 3c 4d 69 63 72 6f 73 6f 66 74 2e 53 6f 75 6e 64 65 72 2e 50 72 6f 74 6f 63 6f 6c 73 2e 46 72 61 6d 65 3e } //00 00  System.Collections.Generic.IComparer<Microsoft.Sounder.Protocols.Frame>
	condition:
		any of ($a_*)
 
}