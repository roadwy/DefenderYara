
rule Trojan_MacOS_MacFileOpener_B_MTB{
	meta:
		description = "Trojan:MacOS/MacFileOpener.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 4d 61 69 6e 41 70 70 } //1 killMainApp
		$a_00_1 = {4c 69 62 72 61 72 79 2f 50 72 65 66 65 72 65 6e 63 65 73 2f 63 6f 6d 2e 70 63 76 61 72 6b 2e 4d 61 63 2d 46 69 6c 65 2d 4f 70 65 6e 65 72 2e 70 6c 69 73 74 } //1 Library/Preferences/com.pcvark.Mac-File-Opener.plist
		$a_00_2 = {2f 4c 69 62 72 61 72 79 2f 43 61 63 68 65 73 2f 63 6f 6d 2e 70 63 76 61 72 6b 2e 4d 61 63 2d 46 69 6c 65 2d 4f 70 65 6e 65 72 } //1 /Library/Caches/com.pcvark.Mac-File-Opener
		$a_00_3 = {74 72 6b 2e 61 64 76 61 6e 63 65 64 6d 61 63 63 6c 65 61 6e 65 72 2e 63 6f 6d 2f 74 72 61 63 6b 65 72 77 63 66 73 72 76 2f 74 72 61 63 6b 65 72 2e 73 76 63 2f 74 72 61 63 6b 4f 66 66 65 72 73 41 63 63 65 70 74 65 64 2f 3f 71 3d 70 78 6c 3d 25 40 } //1 trk.advancedmaccleaner.com/trackerwcfsrv/tracker.svc/trackOffersAccepted/?q=pxl=%@
		$a_00_4 = {2f 4c 69 62 72 61 72 79 2f 4c 6f 67 73 2f 4d 61 63 20 46 69 6c 65 20 4f 70 65 6e 65 72 2e 6c 6f 67 } //1 /Library/Logs/Mac File Opener.log
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}