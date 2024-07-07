
rule Trojan_AndroidOS_Kasandra_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Kasandra.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 72 6f 69 64 6a 61 63 6b 2e 6e 65 74 2f 41 63 63 65 73 73 2f 44 4a 36 2e 70 68 70 } //1 droidjack.net/Access/DJ6.php
		$a_00_1 = {64 72 6f 69 64 6a 61 63 6b 2e 6e 65 74 2f 73 74 6f 72 65 52 65 70 6f 72 74 2e 70 68 70 } //1 droidjack.net/storeReport.php
		$a_00_2 = {2f 44 4a 54 6d 70 63 70 44 49 52 2e 7a 69 70 } //1 /DJTmpcpDIR.zip
		$a_00_3 = {53 61 6e 64 72 6f 52 61 74 5f 52 65 63 6f 72 64 65 64 53 4d 53 5f 44 61 74 61 62 61 73 65 } //1 SandroRat_RecordedSMS_Database
		$a_00_4 = {53 61 6e 64 72 6f 52 61 74 5f 43 61 6c 6c 52 65 63 6f 72 64 73 5f 44 61 74 61 62 61 73 65 } //1 SandroRat_CallRecords_Database
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}