
rule Trojan_BAT_Disabler_NITA_MTB{
	meta:
		description = "Trojan:BAT/Disabler.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 5f 65 78 65 } //1 Kill_exe
		$a_01_1 = {46 69 6c 65 53 68 61 72 65 57 72 69 74 65 } //1 FileShareWrite
		$a_01_2 = {67 64 69 5f 70 61 79 6c 6f 61 64 } //1 gdi_payload
		$a_01_3 = {66 69 6e 61 6c 5f 70 61 79 6c 6f 61 64 } //1 final_payload
		$a_01_4 = {6b 69 6c 6c 5f 70 72 6f 63 65 73 73 } //1 kill_process
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}