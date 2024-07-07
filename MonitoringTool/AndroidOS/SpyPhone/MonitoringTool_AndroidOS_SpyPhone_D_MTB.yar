
rule MonitoringTool_AndroidOS_SpyPhone_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyPhone.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 48 52 30 63 48 4d 36 4c 79 39 6a 62 32 31 31 62 6d 6c 6a 59 58 52 70 62 32 35 75 62 33 63 75 59 32 39 74 4c 33 4e 6a 63 6d 6c 77 64 48 4d 76 59 58 42 77 63 31 39 79 5a 57 64 70 63 33 52 6c 63 6c 39 68 62 6d 46 73 65 58 4e 70 63 79 35 77 61 48 41 3d } //1 aHR0cHM6Ly9jb211bmljYXRpb25ub3cuY29tL3NjcmlwdHMvYXBwc19yZWdpc3Rlcl9hbmFseXNpcy5waHA=
		$a_01_1 = {61 48 52 30 63 48 4d 36 4c 79 39 6a 62 32 31 31 62 6d 6c 6a 59 58 52 70 62 32 35 75 62 33 63 75 59 32 39 74 4c 33 4e 6a 63 6d 6c 77 64 48 4d 76 59 58 42 77 63 31 39 31 63 47 52 68 64 47 56 66 59 57 35 68 62 48 6c 7a 61 58 4d 75 63 47 68 77 } //1 aHR0cHM6Ly9jb211bmljYXRpb25ub3cuY29tL3NjcmlwdHMvYXBwc191cGRhdGVfYW5hbHlzaXMucGhw
		$a_01_2 = {73 74 61 72 74 57 68 61 74 73 53 70 61 6d } //1 startWhatsSpam
		$a_01_3 = {70 69 6c 74 75 72 65 6e 74 2e 63 6f 6d } //1 pilturent.com
		$a_01_4 = {65 6e 61 62 6c 65 5f 62 72 6f 77 73 65 72 5f 6f 67 61 64 73 } //1 enable_browser_ogads
		$a_01_5 = {6f 67 61 64 73 5f 6a 61 76 61 73 63 72 69 70 74 } //1 ogads_javascript
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}