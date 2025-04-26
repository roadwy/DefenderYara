
rule Trojan_AndroidOS_Opfake_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Opfake.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 2f 61 6e 64 72 6f 69 64 2f 61 70 70 2f 49 6e 73 74 61 6c 6c 41 63 74 69 76 69 74 79 } //1 net/android/app/InstallActivity
		$a_01_1 = {6e 65 74 2f 61 6e 64 72 6f 69 64 2f 61 70 70 2f 4c 6f 61 64 65 72 41 63 74 69 76 69 74 79 } //1 net/android/app/LoaderActivity
		$a_01_2 = {46 4a 65 32 6a 73 76 65 6f 48 48 4d 70 78 76 56 } //1 FJe2jsveoHHMpxvV
		$a_01_3 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //1 sendTextMessage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}