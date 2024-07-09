
rule Adware_MacOS_NewTab_A{
	meta:
		description = "Adware:MacOS/NewTab.A,SIGNATURE_TYPE_MACHOHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 75 73 72 2f 62 69 6e 2f 64 69 74 74 6f } //1 /usr/bin/ditto
		$a_02_1 = {43 6f 6e 74 65 6e 74 73 2f 4c 69 62 72 61 72 79 2f 4c 6f 67 69 6e 49 74 65 6d 73 2f [0-40] 2e 61 70 70 } //3
		$a_01_2 = {4c 53 51 75 61 72 61 6e 74 69 6e 65 44 61 74 61 55 52 4c 53 74 72 69 6e 67 } //2 LSQuarantineDataURLString
		$a_01_3 = {4c 53 51 75 61 72 61 6e 74 69 6e 65 45 76 65 6e 74 49 64 65 6e 74 69 66 69 65 72 } //2 LSQuarantineEventIdentifier
		$a_01_4 = {6f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d 56 65 72 73 69 6f 6e } //3 operatingSystemVersion
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*3) >=11
 
}