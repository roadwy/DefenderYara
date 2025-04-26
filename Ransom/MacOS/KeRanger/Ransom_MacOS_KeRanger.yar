
rule Ransom_MacOS_KeRanger{
	meta:
		description = "Ransom:MacOS/KeRanger,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 52 65 73 6f 75 72 63 65 73 2f 47 65 6e 65 72 61 6c 2e 72 74 66 } //2 /Resources/General.rtf
		$a_00_1 = {2f 4c 69 62 72 61 72 79 2f 6b 65 72 6e 65 6c 5f 73 65 72 76 69 63 65 } //1 /Library/kernel_service
		$a_00_2 = {2f 4c 69 62 72 61 72 79 2f 2e 6b 65 72 6e 65 6c 5f 70 69 64 } //1 /Library/.kernel_pid
		$a_00_3 = {2f 4c 69 62 72 61 72 79 2f 2e 6b 65 72 6e 65 6c 5f 74 69 6d 65 } //1 /Library/.kernel_time
		$a_00_4 = {2f 4c 69 62 72 61 72 79 2f 2e 6b 65 72 6e 65 6c 5f 63 6f 6d 70 6c 65 74 65 } //1 /Library/.kernel_complete
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}