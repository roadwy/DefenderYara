
rule Trojan_Win64_ShellLoader_SXC_MTB{
	meta:
		description = "Trojan:Win64/ShellLoader.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 05 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 6f 6d 6d 61 6e 64 20 22 24 61 63 74 69 6f 6e 20 3d 20 4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 41 63 74 69 6f 6e 20 2d 45 78 65 63 75 74 65 20 27 77 73 63 72 69 70 74 2e 65 78 65 27 20 2d 41 72 67 75 6d 65 6e 74 20 27 5c 22 25 73 5c 22 27 3b } //powershell -command "$action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument '\"%s\"';  20
		$a_80_1 = {24 74 72 69 67 67 65 72 20 3d 20 4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 54 72 69 67 67 65 72 20 2d 41 74 4c 6f 67 4f 6e 3b } //$trigger = New-ScheduledTaskTrigger -AtLogOn;  20
		$a_80_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 6f 6d 6d 61 6e 64 20 22 69 66 28 47 65 74 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 20 2d 54 61 73 6b 4e 61 6d 65 20 27 25 73 27 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 29 20 7b 20 65 78 69 74 20 30 20 7d 20 65 6c 73 65 20 7b 20 65 78 69 74 20 31 20 7d } //powershell -command "if(Get-ScheduledTask -TaskName '%s' -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }  15
		$a_80_3 = {70 61 79 6c 6f 61 64 } //payload  10
		$a_80_4 = {44 69 73 61 62 6c 65 2d 4e 65 74 41 64 61 70 74 65 72 20 2d 4e 61 6d 65 20 27 25 73 27 20 2d 43 6f 6e 66 69 72 6d 3a 24 66 61 6c 73 65 3b } //Disable-NetAdapter -Name '%s' -Confirm:$false;  5
	condition:
		((#a_80_0  & 1)*20+(#a_80_1  & 1)*20+(#a_80_2  & 1)*15+(#a_80_3  & 1)*10+(#a_80_4  & 1)*5) >=70
 
}