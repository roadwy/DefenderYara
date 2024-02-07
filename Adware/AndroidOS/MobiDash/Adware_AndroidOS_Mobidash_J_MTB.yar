
rule Adware_AndroidOS_Mobidash_J_MTB{
	meta:
		description = "Adware:AndroidOS/Mobidash.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 69 64 6c 65 6c 61 77 66 69 72 6d 2f 65 6d 70 69 72 65 74 79 63 6f 6f 6e 67 61 6d 65 } //0a 00  com/idlelawfirm/empiretycoongame
		$a_01_1 = {76 69 6a 61 2f 73 75 6d 6d 65 72 2f 62 65 61 63 68 2f 6c 61 75 6e 63 68 65 72 } //0a 00  vija/summer/beach/launcher
		$a_01_2 = {7a 65 78 69 63 61 2f 61 70 70 2f 73 75 6d 6d 65 72 2f 77 61 6c 6c 70 61 70 65 72 73 } //0a 00  zexica/app/summer/wallpapers
		$a_01_3 = {2f 65 78 70 6f 2f 70 72 6f 67 72 65 73 73 79 6f 75 72 73 65 6c 66 2f } //01 00  /expo/progressyourself/
		$a_01_4 = {6f 6e 55 70 67 72 61 64 65 } //01 00  onUpgrade
		$a_01_5 = {67 65 74 50 61 63 6b 61 67 65 49 6e 66 6f } //00 00  getPackageInfo
	condition:
		any of ($a_*)
 
}