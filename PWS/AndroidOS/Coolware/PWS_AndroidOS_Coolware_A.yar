
rule PWS_AndroidOS_Coolware_A{
	meta:
		description = "PWS:AndroidOS/Coolware.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 73 70 63 62 65 61 75 74 79 2f 63 61 6d 61 70 70 } //01 00  Lcom/spcbeauty/camapp
		$a_01_1 = {42 41 53 45 5f 55 52 4c } //01 00  BASE_URL
		$a_01_2 = {67 65 74 42 41 53 45 5f 55 52 4c } //01 00  getBASE_URL
		$a_01_3 = {74 6f 53 6c 69 6d 6d 69 6e 67 } //01 00  toSlimming
		$a_01_4 = {4c 63 6f 6d 2f 61 6c 69 62 61 62 61 2f 61 6e 64 72 6f 69 64 2f 61 72 6f 75 74 65 72 2f 66 61 63 61 64 65 2f 50 6f 73 74 63 61 72 64 } //01 00  Lcom/alibaba/android/arouter/facade/Postcard
		$a_01_5 = {74 6f 43 61 72 74 6f 6f 6e } //01 00  toCartoon
		$a_01_6 = {6a 75 6d 70 57 69 74 68 } //01 00  jumpWith
		$a_01_7 = {2f 61 70 70 2f 73 6c 69 6d 6d 69 6e 67 2f } //00 00  /app/slimming/
	condition:
		any of ($a_*)
 
}