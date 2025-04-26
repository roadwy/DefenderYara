
rule Adware_MacOS_AdwRemPro_A_MTB{
	meta:
		description = "Adware:MacOS/AdwRemPro.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 64 77 61 72 65 2d 52 65 6d 6f 76 61 6c 2d 50 72 6f 2f 73 72 63 2f } //5 Adware-Removal-Pro/src/
		$a_00_1 = {41 70 70 44 65 6c 65 67 61 74 65 20 69 73 49 6e 54 72 61 73 68 44 69 72 } //1 AppDelegate isInTrashDir
		$a_00_2 = {41 64 77 61 72 65 52 65 6d 6f 76 61 6c 50 72 6f } //1 AdwareRemovalPro
		$a_00_3 = {61 70 70 6c 69 63 61 74 69 6f 6e 44 69 64 48 69 64 65 3a } //1 applicationDidHide:
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=7
 
}