
rule TrojanSpy_AndroidOS_Micropsia_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Micropsia.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {6f 6e 50 6f 73 74 45 78 65 63 75 74 65 3a 20 64 65 6c 65 74 65 20 61 70 6b 20 72 65 73 75 6c 74 } //1 onPostExecute: delete apk result
		$a_01_1 = {41 70 6b 20 44 6f 77 6e 6c 6f 61 64 65 64 20 3f } //1 Apk Downloaded ?
		$a_00_2 = {2f 61 6e 64 72 6f 69 64 2f 73 79 73 2f 63 6f 6e 74 61 63 74 73 } //1 /android/sys/contacts
		$a_00_3 = {72 6f 73 65 2d 73 74 75 72 61 74 2e 69 6e 66 6f 40 64 6f 6d 61 69 6e 73 } //1 rose-sturat.info@domains
		$a_00_4 = {73 6d 73 5f 72 65 63 6f 72 64 69 6e 67 } //1 sms_recording
		$a_00_5 = {63 61 6c 6c 5f 72 65 63 6f 72 64 69 6e 67 } //1 call_recording
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}