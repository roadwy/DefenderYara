
rule Adware_MacOS_DockMaster_K_MTB{
	meta:
		description = "Adware:MacOS/DockMaster.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 8b 3d a0 40 00 00 4c 8b 35 59 3f 00 00 ff 15 93 23 00 00 48 89 c3 48 8d 15 19 2a 00 00 4c 8b 25 72 23 00 00 4c 89 ff 4c 89 f6 41 ff d4 48 8b 35 fa 3f 00 00 48 89 df 41 ff d4 48 89 df } //2
		$a_00_1 = {77 69 6c 6c 5f 69 6e 73 74 61 6c 6c 5f 75 70 64 61 74 65 } //1 will_install_update
		$a_00_2 = {67 65 74 52 75 6e 6e 69 6e 67 41 70 70 6c 69 63 61 74 69 6f 6e 73 } //1 getRunningApplications
		$a_00_3 = {67 65 74 4d 61 63 53 65 72 69 61 6c 4e 75 6d 62 65 72 } //1 getMacSerialNumber
		$a_00_4 = {73 65 74 41 75 74 6f 6d 61 74 69 63 61 6c 6c 79 44 6f 77 6e 6c 6f 61 64 73 55 70 64 61 74 65 73 } //1 setAutomaticallyDownloadsUpdates
		$a_00_5 = {67 65 74 48 61 72 64 77 61 72 65 55 75 69 64 } //1 getHardwareUuid
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}