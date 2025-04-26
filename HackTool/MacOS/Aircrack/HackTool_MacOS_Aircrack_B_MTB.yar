
rule HackTool_MacOS_Aircrack_B_MTB{
	meta:
		description = "HackTool:MacOS/Aircrack.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 61 69 72 63 72 61 63 6b 2d 6e 67 2e 6f 72 67 } //1 www.aircrack-ng.org
		$a_00_1 = {61 69 72 63 72 61 63 6b 2d 6e 67 2e 63 } //1 aircrack-ng.c
		$a_00_2 = {53 45 4c 45 43 54 20 70 6d 6b 2e 50 4d 4b 2c 20 70 61 73 73 77 64 2e 70 61 73 73 77 64 20 46 52 4f 4d 20 70 6d 6b } //1 SELECT pmk.PMK, passwd.passwd FROM pmk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}