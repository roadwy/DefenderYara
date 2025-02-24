
rule Trojan_AndroidOS_Opfake_OT{
	meta:
		description = "Trojan:AndroidOS/Opfake.OT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 6d 31 6d 51 43 3f 2e 59 56 73 20 51 64 56 4c 43 47 64 4f 64 68 } //1 km1mQC?.YVs QdVLCGdOdh
		$a_01_1 = {6f 52 3f 64 40 2e 51 56 64 3f 55 64 43 64 2e 31 64 3f } //1 oR?d@.QVd?UdCd.1d?
		$a_01_2 = {6d 52 63 3f 45 2e 63 60 6d 59 59 60 29 43 56 2e 31 2e 56 41 } //1 mRc?E.c`mYY`)CV.1.VA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}