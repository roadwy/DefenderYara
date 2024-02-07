
rule TrojanDropper_O97M_IcedID_PDL_MTB{
	meta:
		description = "TrojanDropper:O97M/IcedID.PDL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {29 66 6f 72 69 3d 6c 2d 31 74 6f 30 73 74 65 70 2d 32 62 28 69 6e 64 65 78 29 3d 63 62 79 74 65 28 63 6c 6e 67 28 68 2b 28 6d 69 64 28 73 2c 69 2c 32 29 29 29 29 69 6e 64 65 78 3d 69 6e 64 65 78 2b 31 6e 65 78 74 } //01 00  )fori=l-1to0step-2b(index)=cbyte(clng(h+(mid(s,i,2))))index=index+1next
		$a_01_1 = {3d 70 72 65 70 5f 64 63 28 36 30 2c 35 31 30 2c 39 39 2c 32 29 66 6f 72 69 3d 31 74 6f 6c 65 6e 28 73 29 73 74 65 70 68 6f 70 73 74 6d 70 3d 73 74 6d 70 2b 64 28 63 69 6e 74 28 6d 69 64 28 73 2c 69 2c 68 6f 70 29 29 29 6e 65 78 74 69 } //01 00  =prep_dc(60,510,99,2)fori=1tolen(s)stephopstmp=stmp+d(cint(mid(s,i,hop)))nexti
		$a_01_2 = {3d 22 61 62 6e 6f 72 6d 61 6c 74 65 72 6d 69 6e 61 74 69 6f 6e 22 6d 73 67 62 6f 78 78 2c 76 62 63 72 69 74 69 63 61 6c 65 6e 64 69 66 65 6e 64 73 75 62 70 75 62 6c 69 63 66 75 6e 63 74 69 6f 6e 64 63 28 73 61 73 73 74 72 69 6e 67 2c 6f 70 74 69 6f 6e 61 6c 68 6f 70 61 73 6c 6f 6e 67 3d 33 29 61 73 73 74 72 69 6e 67 64 69 6d 64 } //01 00  ="abnormaltermination"msgboxx,vbcriticalendifendsubpublicfunctiondc(sasstring,optionalhopaslong=3)asstringdimd
		$a_01_3 = {28 22 2e 67 69 74 69 6e 67 6f 72 65 22 29 3c 3e 22 22 74 68 65 6e 27 6d 73 67 62 6f 78 22 74 68 69 73 69 73 61 6e 69 6e 63 6f 6d 70 61 74 69 62 6c 65 76 65 72 73 69 6f 6e 2c 70 6c 65 61 73 65 2c 75 70 64 61 74 65 2e 22 2c 76 62 69 6e 66 6f 72 6d 61 74 69 6f 6e 65 6c 73 65 69 66 6c 68 5f 6d 6f 64 65 74 68 65 6e 64 61 74 61 3d 73 77 69 74 63 68 73 69 64 65 73 28 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e } //00 00  (".gitingore")<>""then'msgbox"thisisanincompatibleversion,please,update.",vbinformationelseiflh_modethendata=switchsides(activedocument.
	condition:
		any of ($a_*)
 
}