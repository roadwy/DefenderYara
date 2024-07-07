
rule Trojan_MacOS_OpinionSpy_H_MTB{
	meta:
		description = "Trojan:MacOS/OpinionSpy.H!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {75 6e 69 6e 73 74 61 6c 6c 20 6d 61 63 6d 65 74 65 72 } //1 uninstall macmeter
		$a_00_1 = {2f 63 6f 6d 73 63 6f 72 65 2f 77 6f 72 6b 69 6e 67 63 6f 70 79 2f 4d 61 63 53 6e 69 66 66 65 72 2f 55 6e 49 6e 73 74 61 6c 6c 54 6f 6f 6c } //3 /comscore/workingcopy/MacSniffer/UnInstallTool
		$a_00_2 = {55 6e 69 6e 73 74 61 6c 6c 4d 61 69 6e 43 6f 6e 74 72 6f 6c 6c 65 72 20 73 65 74 42 72 61 6e 64 3a } //1 UninstallMainController setBrand:
		$a_00_3 = {75 6e 69 6e 73 74 61 6c 6c 68 65 6c 70 65 72 74 6f 6f 6c } //1 uninstallhelpertool
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=6
 
}