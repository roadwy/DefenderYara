
rule TrojanDownloader_O97M_IcedID_ZSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.ZSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2c 30 26 2c 30 26 2c 30 26 2c 30 26 72 65 64 69 6d 28 31 29 65 6e 64 73 75 62 66 75 6e 63 74 69 6f 6e 28 29 3d } //1 ,0&,0&,0&,0&redim(1)endsubfunction()=
		$a_01_1 = {66 6f 72 3d 30 74 6f 28 29 2d 31 73 74 65 70 32 3d 2f 32 28 29 3d 32 35 35 2d 28 26 28 2c 29 26 28 2c 2b 31 29 29 6e 65 78 74 3d 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e } //1 for=0to()-1step2=/2()=255-(&(,)&(,+1))next=endfunctionfunction
		$a_01_2 = {26 6d 69 64 28 73 74 72 69 6e 70 75 74 2c 6c 65 6e 28 73 74 72 69 6e 70 75 74 29 2d 6b 2c 31 29 6e 65 78 74 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 28 2c 29 3d 6d 69 64 28 2c 2b 31 2c 31 29 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 28 29 3d } //1 &mid(strinput,len(strinput)-k,1)nextendfunctionfunction(,)=mid(,+1,1)endfunctionfunction()=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}