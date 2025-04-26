
rule Trojan_Win32_Agent_BB{
	meta:
		description = "Trojan:Win32/Agent.BB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 63 73 72 73 73 2e 65 78 65 } //1 C:\WINDOWS\csrss.exe
		$a_01_1 = {20 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 } //1  if exist "%s" goto Repeat
		$a_00_2 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //1 InternetExplorer.Application
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 73 5c 33 } //1 Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3
		$a_00_4 = {43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 79 00 70 00 65 00 3a 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 78 00 2d 00 77 00 77 00 77 00 2d 00 66 00 6f 00 72 00 6d 00 2d 00 75 00 72 00 6c 00 65 00 6e 00 63 00 6f 00 64 00 65 00 64 00 } //1 Content-Type: application/x-www-form-urlencoded
		$a_01_5 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //1 InternetGetConnectedState
		$a_01_6 = {20 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 62 00 6f 00 64 00 79 00 2e 00 6f 00 6e 00 63 00 6f 00 6e 00 74 00 65 00 78 00 74 00 6d 00 65 00 6e 00 75 00 3d 00 6d 00 66 00 3c 00 2f 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00 } //1  document.body.oncontextmenu=mf</script>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}