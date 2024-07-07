
rule Ransom_AndroidOS_Slocker_D_MTB{
	meta:
		description = "Ransom:AndroidOS/Slocker.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 71 69 61 6e 6d 6f 2e 72 6f 6f 74 2e 4d 79 41 64 6d 69 6e } //1 com.qianmo.root.MyAdmin
		$a_01_1 = {61 63 74 69 76 69 74 65 44 65 76 69 63 65 } //1 activiteDevice
		$a_01_2 = {72 65 73 65 74 50 61 73 73 77 6f 72 64 } //1 resetPassword
		$a_01_3 = {4c 61 64 72 74 2f 41 44 52 54 4c 6f 67 43 61 74 52 65 61 64 65 72 } //1 Ladrt/ADRTLogCatReader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}