
rule Ransom_AndroidOS_Slocker_A_MTB{
	meta:
		description = "Ransom:AndroidOS/Slocker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 64 6d 69 6e 52 65 63 65 69 76 65 72 2e 4c 6f 63 6b 65 72 } //1 AdminReceiver.Locker
		$a_00_1 = {73 79 73 74 65 6d 5f 75 70 64 61 74 65 2e 61 70 6b } //1 system_update.apk
		$a_00_2 = {43 6f 6d 6d 61 6e 64 73 2e 69 6e 69 74 69 61 6c 43 6f 6d 6d 61 6e 64 } //1 Commands.initialCommand
		$a_00_3 = {64 65 76 69 63 65 5f 62 6c 6f 63 6b } //1 device_block
		$a_00_4 = {63 6f 6e 74 61 63 74 73 4c 69 73 74 53 65 6e 64 } //1 contactsListSend
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}