
rule Trojan_Win32_Agent_AAI{
	meta:
		description = "Trojan:Win32/Agent.AAI,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 36 30 73 65 5f 46 72 61 6d 65 } //01 00  360se_Frame
		$a_01_1 = {20 73 79 73 74 65 6d 33 32 5c 69 6d 65 5c 70 69 6e 67 20 2d 6e 20 } //01 00   system32\ime\ping -n 
		$a_01_2 = {65 63 68 6f 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 5e 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 5e 22 29 2e 52 75 6e 28 5e 22 63 6d 64 20 2f 63 20 78 63 6f 70 79 } //01 00  echo WScript.CreateObject(^"WScript.Shell^").Run(^"cmd /c xcopy
		$a_01_3 = {65 63 68 6f 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 72 75 6e 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 72 65 67 65 64 69 74 2f 73 } //01 00  echo CreateObject("wscript.shell").run "cmd.exe /c regedit/s
		$a_01_4 = {5e 22 5e 26 43 68 72 28 33 34 29 29 2c 76 62 48 69 64 65 3e } //00 00  ^"^&Chr(34)),vbHide>
	condition:
		any of ($a_*)
 
}