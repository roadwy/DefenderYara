
rule Trojan_AndroidOS_Rootnik_B_xp{
	meta:
		description = "Trojan:AndroidOS/Rootnik.B!xp,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 0b 00 00 "
		
	strings :
		$a_00_0 = {2f 2e 61 6e 64 72 6f 69 64 2f 2e 73 79 73 74 65 6d 2f 2e 63 7a 2f 2e 6f 70 2f 70 61 63 6b 61 67 65 2e 70 72 6f 70 65 72 74 69 65 73 } //1 /.android/.system/.cz/.op/package.properties
		$a_00_1 = {2f 48 65 61 6c 74 68 52 65 63 6f 72 64 2f 74 65 73 74 2e 6c 6f 67 } //1 /HealthRecord/test.log
		$a_00_2 = {2f 73 64 63 61 72 64 2f 2e 72 69 64 } //1 /sdcard/.rid
		$a_00_3 = {44 61 74 61 2f 2e 72 6f 6f 74 67 65 6e 69 75 73 } //1 Data/.rootgenius
		$a_00_4 = {63 6f 6d 2e 77 6f 6d 69 2e 61 63 74 69 76 69 74 79 2e } //1 com.womi.activity.
		$a_00_5 = {2f 2f 7a 66 61 6e 64 63 7a 2e 61 6c 70 68 61 66 61 6c 61 62 2e 63 6f 6d 3a 38 35 38 35 } //1 //zfandcz.alphafalab.com:8585
		$a_00_6 = {2f 2f 6f 66 66 65 72 32 2e 6a 6f 79 6d 65 64 69 61 2e 6d 6f 62 69 2f 69 6e 64 65 78 2e 70 68 70 3f 72 3d 61 70 69 2f 6f 66 66 65 72 63 6c 69 63 6b 26 6f 66 66 65 72 5f 69 64 3d 32 33 39 31 36 26 61 66 66 5f 69 64 } //1 //offer2.joymedia.mobi/index.php?r=api/offerclick&offer_id=23916&aff_id
		$a_02_7 = {3a 2f 2f 71 64 63 75 30 31 2e 62 61 69 64 75 70 63 73 2e 63 6f 6d 2f 66 69 6c 65 2f [0-30] 3f 62 6b 74 3d } //1
		$a_00_8 = {63 6f 6d 2e 69 53 65 63 75 72 69 74 79 43 61 6d 43 6c 69 65 6e 74 2d 31 2e 61 70 6b } //1 com.iSecurityCamClient-1.apk
		$a_00_9 = {2f 2f 70 75 73 68 2e 64 65 6e 67 61 6e 64 72 6f 69 64 2e 63 6f 6d 2f 67 65 74 72 6f 6f 74 6a 61 72 69 6e 66 6f } //1 //push.dengandroid.com/getrootjarinfo
		$a_02_10 = {6d 6f 75 6e 74 20 2d 6f 20 72 65 6d 6f 75 6e 74 2c 72 77 20 2f 73 79 73 74 65 6d [0-02] 65 63 68 6f 20 72 6f 6f 74 65 64 20 3e 20 2f 73 79 73 74 65 6d 2f 72 6f 6f 74 65 64 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_02_10  & 1)*1) >=5
 
}