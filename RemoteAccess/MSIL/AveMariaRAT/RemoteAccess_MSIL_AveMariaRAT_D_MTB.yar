
rule RemoteAccess_MSIL_AveMariaRAT_D_MTB{
	meta:
		description = "RemoteAccess:MSIL/AveMariaRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 11 01 02 8e 69 5d 02 11 01 02 8e 69 5d 91 11 00 11 01 11 00 8e 69 5d 91 61 28 ?? 00 00 0a 02 11 01 17 58 02 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 38 } //2
		$a_01_1 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}