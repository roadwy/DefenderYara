
rule Trojan_AndroidOS_FakeDoc_B_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeDoc.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 73 61 76 65 62 61 74 74 65 72 79 2f 6b 69 6c 6c 65 72 2f 70 72 6f 2f 45 61 73 79 54 61 73 6b 4b 69 6c 6c 65 72 } //02 00  Lcom/savebattery/killer/pro/EasyTaskKiller
		$a_01_1 = {67 65 74 52 65 63 6f 72 64 65 64 4b 69 6c 6c 65 64 41 70 70 73 } //02 00  getRecordedKilledApps
		$a_01_2 = {77 72 69 74 65 44 65 76 69 63 65 54 6f 44 42 } //01 00  writeDeviceToDB
		$a_01_3 = {2f 50 6f 73 74 2f 41 64 64 44 65 76 69 63 65 } //01 00  /Post/AddDevice
		$a_01_4 = {2f 50 6f 73 74 2f 54 72 61 66 66 69 63 2f } //00 00  /Post/Traffic/
	condition:
		any of ($a_*)
 
}