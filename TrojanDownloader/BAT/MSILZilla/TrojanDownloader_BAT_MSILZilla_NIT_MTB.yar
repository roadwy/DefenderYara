
rule TrojanDownloader_BAT_MSILZilla_NIT_MTB{
	meta:
		description = "TrojanDownloader:BAT/MSILZilla.NIT!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {76 00 6d 00 77 00 61 00 72 00 65 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 } //2 vmwareservice
		$a_01_1 = {56 00 42 00 6f 00 78 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //2 VBoxService
		$a_01_2 = {25 00 73 00 79 00 73 00 74 00 65 00 6d 00 64 00 72 00 69 00 76 00 65 00 25 00 } //2 %systemdrive%
		$a_01_3 = {76 00 6d 00 74 00 6f 00 6f 00 6c 00 73 00 64 00 } //1 vmtoolsd
		$a_01_4 = {76 00 6d 00 77 00 61 00 72 00 65 00 74 00 72 00 61 00 79 00 } //1 vmwaretray
		$a_01_5 = {78 00 36 00 34 00 64 00 62 00 67 00 } //1 x64dbg
		$a_01_6 = {66 00 69 00 64 00 64 00 6c 00 65 00 72 00 } //1 fiddler
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}