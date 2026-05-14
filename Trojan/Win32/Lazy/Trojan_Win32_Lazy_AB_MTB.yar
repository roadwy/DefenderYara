
rule Trojan_Win32_Lazy_AB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 7c 24 60 10 8d 44 24 4c 0f 43 44 24 4c 8a 04 10 2a 04 91 88 44 24 13 3b de 73 2e 8a 4c 24 13 8d 43 01 89 44 24 38 83 fe 10 8d 44 24 28 0f 43 c7 88 0c 18 c6 44 18 01 00 8b 74 24 3c 8b 5c 24 38 8b 7c 24 28 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Lazy_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 ce 89 f0 c1 e0 ?? 01 f0 89 c1 c1 e9 ?? 31 c1 0f b7 44 5a ?? 43 66 85 c0 75 } //30
		$a_03_1 = {1f 40 00 83 cb ?? 0f b6 db 69 f6 ?? ?? ?? ?? 01 de 0f b7 5c 4f ?? 41 66 85 db 75 } //30
		$a_03_2 = {01 00 00 0f b6 5c 02 ?? 88 9c 04 ?? 01 00 00 0f b6 54 02 ?? 88 94 04 ?? 01 00 00 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*30+(#a_03_2  & 1)*20) >=50
 
}
rule Trojan_Win32_Lazy_AB_MTB_3{
	meta:
		description = "Trojan:Win32/Lazy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 61 63 74 69 6f 6e 31 20 3d 20 4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 41 63 74 69 6f 6e 20 2d 45 78 65 63 75 74 65 20 27 63 6d 64 27 20 2d 41 72 67 75 6d 65 6e 74 20 27 2f 63 20 73 74 61 72 74 20 2f 42 20 2f 6d 69 6e 20 63 6f 70 79 20 2f 59 } //3 $action1 = New-ScheduledTaskAction -Execute 'cmd' -Argument '/c start /B /min copy /Y
		$a_81_1 = {73 74 61 72 74 6d 6f 6e 69 74 6f 72 6e 6f 6b 69 6c 6c } //3 startmonitornokill
		$a_81_2 = {53 65 72 76 69 63 65 48 75 62 2e 65 78 65 } //2 ServiceHub.exe
		$a_81_3 = {53 74 61 72 74 20 52 65 6d 6f 74 65 20 4d 6f 6e 69 74 6f 72 20 53 65 72 76 69 63 65 2e 2e 2e } //2 Start Remote Monitor Service...
		$a_81_4 = {24 74 72 69 67 67 65 72 20 3d 20 4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 54 72 69 67 67 65 72 20 2d 41 74 4c 6f 67 4f 6e 3b } //1 $trigger = New-ScheduledTaskTrigger -AtLogOn;
		$a_81_5 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 69 6c 65 } //1 powershell.exe -NoProfile -ExecutionPolicy Bypass -File
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=12
 
}