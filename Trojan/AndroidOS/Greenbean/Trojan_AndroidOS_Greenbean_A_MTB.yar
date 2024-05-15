
rule Trojan_AndroidOS_Greenbean_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Greenbean.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 05 00 "
		
	strings :
		$a_00_0 = {6f 72 67 2e 69 63 65 63 72 65 61 6d 2e 67 72 65 65 6e 62 65 61 6e } //01 00  org.icecream.greenbean
		$a_00_1 = {73 65 6e 64 4c 6f 63 6b 50 61 74 74 65 72 6e } //01 00  sendLockPattern
		$a_00_2 = {2f 6d 6f 6e 69 74 6f 72 61 70 69 2f 61 70 69 2f 76 31 2f 73 33 2f 75 70 6c 6f 61 64 55 52 4c 3f 73 69 67 6e 61 74 75 72 65 3d } //01 00  /monitorapi/api/v1/s3/uploadURL?signature=
		$a_00_3 = {68 69 64 65 52 75 6e } //01 00  hideRun
		$a_00_4 = {72 65 63 49 6e 66 6f } //01 00  recInfo
		$a_00_5 = {4f 4b 57 53 5f 53 45 4e 44 5f 4d 45 53 53 41 47 45 } //00 00  OKWS_SEND_MESSAGE
	condition:
		any of ($a_*)
 
}