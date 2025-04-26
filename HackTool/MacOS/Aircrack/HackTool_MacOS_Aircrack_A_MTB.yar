
rule HackTool_MacOS_Aircrack_A_MTB{
	meta:
		description = "HackTool:MacOS/Aircrack.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 70 72 69 76 61 74 65 2f 74 6d 70 2f 61 69 72 63 72 61 63 6b 2d 6e 67 } //1 /private/tmp/aircrack-ng
		$a_00_1 = {2f 75 73 72 2f 6c 6f 63 61 6c 2f 43 65 6c 6c 61 72 2f 61 69 72 63 72 61 63 6b 2d 6e 67 } //1 /usr/local/Cellar/aircrack-ng
		$a_00_2 = {53 45 4c 45 43 54 20 70 6d 6b 2e 50 4d 4b 2c 20 70 61 73 73 77 64 2e 70 61 73 73 77 64 20 46 52 4f 4d 20 70 6d 6b } //1 SELECT pmk.PMK, passwd.passwd FROM pmk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}