
rule TrojanDropper_O97M_IcedID_PDK_MTB{
	meta:
		description = "TrojanDropper:O97M/IcedID.PDK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 63 61 6c 6c 62 79 6e 61 6d 65 28 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2c 90 02 0a 28 22 90 02 20 22 29 2c 76 62 67 65 74 2c 90 00 } //01 00 
		$a_01_1 = {66 6f 72 3d 31 74 6f 6c 65 6e 28 29 73 74 65 70 32 28 28 2d 31 29 2f 32 29 3d 63 64 65 63 28 26 6d 69 64 28 2c 2c 32 29 29 6e 65 78 74 3d 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 28 29 } //01 00  for=1tolen()step2((-1)/2)=cdec(&mid(,,2))next=endfunctionfunction()
		$a_01_2 = {66 6f 72 6b 3d 30 74 6f 6c 65 6e 28 73 29 2d 31 73 68 69 66 74 3d 28 61 73 63 28 6d 69 64 28 6b 65 79 2c 28 6b 6d 6f 64 6c 65 6e 28 6b 65 79 29 29 2b 31 2c 31 29 29 6d 6f 64 6c 65 6e 28 73 29 29 2b 31 } //01 00  fork=0tolen(s)-1shift=(asc(mid(key,(kmodlen(key))+1,1))modlen(s))+1
		$a_01_3 = {3d 6d 69 64 28 73 2c 31 2c 70 6f 73 2d 31 29 26 6d 69 64 28 73 2c 70 6f 73 2b 31 2c 6c 65 6e 28 73 29 29 65 6e 64 66 75 6e 63 74 69 6f 6e 73 75 62 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 64 69 6d 28 29 } //00 00  =mid(s,1,pos-1)&mid(s,pos+1,len(s))endfunctionsubdocument_open()dim()
	condition:
		any of ($a_*)
 
}