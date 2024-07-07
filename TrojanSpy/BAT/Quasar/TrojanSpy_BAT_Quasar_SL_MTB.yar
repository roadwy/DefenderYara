
rule TrojanSpy_BAT_Quasar_SL_MTB{
	meta:
		description = "TrojanSpy:BAT/Quasar.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 31 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 server1.Resources.resources
		$a_01_1 = {43 6c 6c 69 6b 69 6f 6d 20 4b 66 73 64 67 67 69 6d 6f 20 4d 65 64 69 61 } //1 Cllikiom Kfsdggimo Media
		$a_01_2 = {73 65 72 76 65 72 31 2e 65 78 65 } //1 server1.exe
		$a_01_3 = {32 30 32 31 20 43 6c 6c 69 6b 69 6f 6d 20 4b 66 73 64 67 67 69 6d 6f } //1 2021 Cllikiom Kfsdggimo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}