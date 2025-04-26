
rule Trojan_AndroidOS_lotoor_n{
	meta:
		description = "Trojan:AndroidOS/lotoor.n,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 69 74 73 62 6c 61 6e 6b 2e 62 6c 61 6e 6b 61 70 70 } //1 com.itsblank.blankapp
		$a_01_1 = {44 4f 4e 45 20 4e 4f 20 52 45 46 4c } //1 DONE NO REFL
		$a_01_2 = {2f 62 6f 6f 74 6c 6f 61 64 65 72 2e 64 65 78 } //1 /bootloader.dex
		$a_01_3 = {53 54 41 52 54 49 4e 47 20 4d 41 49 4e 20 42 4f 4f 54 53 54 52 41 50 20 4d 45 54 48 4f 44 } //1 STARTING MAIN BOOTSTRAP METHOD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}