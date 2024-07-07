
rule Trojan_BAT_Cfgrator_MTB{
	meta:
		description = "Trojan:BAT/Cfgrator!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {3c 4c 6f 67 6f 6e 54 72 69 67 67 65 72 3e } //1 <LogonTrigger>
		$a_01_1 = {3c 4d 75 6c 74 69 70 6c 65 49 6e 73 74 61 6e 63 65 73 50 6f 6c 69 63 79 3e 53 74 6f 70 45 78 69 73 74 69 6e 67 3c 2f 4d 75 6c 74 69 70 6c 65 49 6e 73 74 61 6e 63 65 73 50 6f 6c 69 63 79 3e } //1 <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
		$a_01_2 = {3c 44 69 73 61 6c 6c 6f 77 53 74 61 72 74 49 66 4f 6e 42 61 74 74 65 72 69 65 73 3e 66 61 6c 73 65 3c 2f 44 69 73 61 6c 6c 6f 77 53 74 61 72 74 49 66 4f 6e 42 61 74 74 65 72 69 65 73 3e } //1 <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
		$a_01_3 = {3c 53 74 6f 70 49 66 47 6f 69 6e 67 4f 6e 42 61 74 74 65 72 69 65 73 3e 74 72 75 65 3c 2f 53 74 6f 70 49 66 47 6f 69 6e 67 4f 6e 42 61 74 74 65 72 69 65 73 3e } //1 <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
		$a_01_4 = {3c 41 6c 6c 6f 77 48 61 72 64 54 65 72 6d 69 6e 61 74 65 3e 66 61 6c 73 65 3c 2f 41 6c 6c 6f 77 48 61 72 64 54 65 72 6d 69 6e 61 74 65 3e } //1 <AllowHardTerminate>false</AllowHardTerminate>
		$a_01_5 = {3c 53 74 61 72 74 57 68 65 6e 41 76 61 69 6c 61 62 6c 65 3e 74 72 75 65 3c 2f 53 74 61 72 74 57 68 65 6e 41 76 61 69 6c 61 62 6c 65 3e } //1 <StartWhenAvailable>true</StartWhenAvailable>
		$a_01_6 = {3c 52 75 6e 4f 6e 6c 79 49 66 4e 65 74 77 6f 72 6b 41 76 61 69 6c 61 62 6c 65 3e 66 61 6c 73 65 3c 2f 52 75 6e 4f 6e 6c 79 49 66 4e 65 74 77 6f 72 6b 41 76 61 69 6c 61 62 6c 65 3e } //1 <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
		$a_01_7 = {3c 41 6c 6c 6f 77 53 74 61 72 74 4f 6e 44 65 6d 61 6e 64 3e 74 72 75 65 3c 2f 41 6c 6c 6f 77 53 74 61 72 74 4f 6e 44 65 6d 61 6e 64 3e } //1 <AllowStartOnDemand>true</AllowStartOnDemand>
		$a_01_8 = {3c 52 75 6e 4f 6e 6c 79 49 66 49 64 6c 65 3e 66 61 6c 73 65 3c 2f 52 75 6e 4f 6e 6c 79 49 66 49 64 6c 65 3e } //1 <RunOnlyIfIdle>false</RunOnlyIfIdle>
		$a_01_9 = {3c 57 61 6b 65 54 6f 52 75 6e 3e 66 61 6c 73 65 3c 2f 57 61 6b 65 54 6f 52 75 6e 3e } //1 <WakeToRun>false</WakeToRun>
		$a_03_10 = {3c 45 78 65 63 75 74 69 6f 6e 54 69 6d 65 4c 69 6d 69 74 3e 90 02 10 3c 2f 45 78 65 63 75 74 69 6f 6e 54 69 6d 65 4c 69 6d 69 74 3e 90 00 } //1
		$a_01_11 = {3c 43 6f 6d 6d 61 6e 64 3e 5b 4c 4f 43 41 54 49 4f 4e 5d 3c 2f 43 6f 6d 6d 61 6e 64 3e } //1 <Command>[LOCATION]</Command>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_03_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}