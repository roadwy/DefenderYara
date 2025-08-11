
rule Trojan_Win64_RustyStealer_GPXB_MTB{
	meta:
		description = "Trojan:Win64/RustyStealer.GPXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {50 72 79 73 6d 61 78 20 53 74 65 61 6c 65 72 20 43 6f 6f 6b 69 65 73 } //2 Prysmax Stealer Cookies
		$a_81_1 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 4b 61 73 70 65 72 73 6b 79 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 4b 61 73 70 65 72 73 6b 79 20 4c 61 62 41 76 61 73 74 } //2 Windows DefenderC:\Program Files\Windows DefenderKasperskyC:\Program Files (x86)\Kaspersky LabAvast
		$a_81_2 = {4c 4f 43 41 4c 41 50 50 44 41 54 41 73 72 63 2f 6d 6f 64 75 6c 65 73 2f 63 6f 6f 6b 69 65 73 2e 72 73 } //1 LOCALAPPDATAsrc/modules/cookies.rs
		$a_81_3 = {63 68 72 6f 6d 65 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 5c 63 68 72 6f 6d 65 2e 65 78 65 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 65 64 67 65 } //1 chromeGoogle\Chrome\Application\chrome.exeGoogle\Chrome\User Dataedge
		$a_81_4 = {73 63 68 74 61 73 6b 73 2f 44 65 6c 65 74 65 2f 54 4e 2f 43 72 65 61 74 65 2f 53 43 2f 52 4c 48 49 47 48 45 53 54 2f 52 55 4e 54 20 41 55 54 48 4f 52 49 54 59 5c 53 59 53 54 45 4d 2f 54 52 5b 43 4c 49 50 50 45 52 5d } //1 schtasks/Delete/TN/Create/SC/RLHIGHEST/RUNT AUTHORITY\SYSTEM/TR[CLIPPER]
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}