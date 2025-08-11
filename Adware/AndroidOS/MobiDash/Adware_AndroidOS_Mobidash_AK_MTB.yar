
rule Adware_AndroidOS_Mobidash_AK_MTB{
	meta:
		description = "Adware:AndroidOS/Mobidash.AK!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 65 78 70 72 65 73 73 65 78 70 65 6e 73 65 2f 62 6c 75 65 74 6f 6f 74 68 2f 70 72 69 6e 74 2f 4d 61 69 6e 5f 41 63 74 69 76 69 74 79 } //1 com/expressexpense/bluetooth/print/Main_Activity
		$a_03_1 = {5d 01 00 54 30 ?? 48 14 01 0c 00 01 7f 14 02 0d 00 01 7f 6e 30 ?? 5d 10 02 54 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}