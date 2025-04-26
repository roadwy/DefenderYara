
rule Ransom_AndroidOS_LockScreen_A{
	meta:
		description = "Ransom:AndroidOS/LockScreen.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {57 35 6b 63 6d 39 70 5a 46 39 70 5a 41 3d 3d } //1 W5kcm9pZF9pZA==
		$a_01_1 = {57 35 6b 63 6d 39 70 5a 43 35 70 62 6e 52 6c 62 6e 51 75 59 32 46 30 5a 57 64 76 63 6e 6b 75 53 45 39 4e 52 } //1 W5kcm9pZC5pbnRlbnQuY2F0ZWdvcnkuSE9NR
		$a_01_2 = {57 35 6b 63 6d 39 70 5a 43 35 70 62 6e 52 6c 62 6e 51 75 59 57 4e 30 61 57 39 75 4c 6c 56 54 52 56 4a 66 55 46 4a 46 55 30 56 4f 56 } //1 W5kcm9pZC5pbnRlbnQuYWN0aW9uLlVTRVJfUFJFU0VOV
		$a_01_3 = {57 35 6b 63 6d 39 70 5a 43 35 70 62 6e 52 6c 62 6e 51 75 59 57 4e 30 61 57 39 75 4c 6c 4e 44 55 6b 56 46 54 6c 39 50 } //1 W5kcm9pZC5pbnRlbnQuYWN0aW9uLlNDUkVFTl9P
		$a_01_4 = {57 35 6b 5a 58 67 75 61 48 52 74 62 } //1 W5kZXguaHRtb
		$a_01_5 = {57 35 6b 63 6d 39 70 5a 43 35 68 63 48 41 75 59 57 4e 30 61 57 39 75 4c 6b 46 45 52 46 39 45 52 56 5a 4a 51 30 56 66 51 55 52 4e 53 55 } //1 W5kcm9pZC5hcHAuYWN0aW9uLkFERF9ERVZJQ0VfQURNSU
		$a_01_6 = {73 74 6f 70 46 6f 72 65 67 72 6f 75 6e 64 } //1 stopForeground
		$a_01_7 = {2f 49 6e 74 72 6f 76 65 72 74 65 64 41 63 74 69 76 69 74 79 3b } //1 /IntrovertedActivity;
		$a_01_8 = {2f 55 6e 76 65 69 6c 73 41 63 74 69 76 69 74 79 3b } //1 /UnveilsActivity;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}
rule Ransom_AndroidOS_LockScreen_A_2{
	meta:
		description = "Ransom:AndroidOS/LockScreen.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {69 6e 74 65 72 72 75 70 74 20 69 6e 73 75 6c 74 61 6c 6c 61 74 69 6f 6e 20 70 72 6f 63 65 73 73 20 61 6e 64 20 63 61 75 73 65 20 6c 6f 73 74 20 6f 66 20 64 61 74 61 } //1 interrupt insultallation process and cause lost of data
		$a_01_1 = {2e 61 70 70 2e 61 63 74 69 6f 6e 2e 41 44 44 5f 44 45 56 49 43 45 5f 41 44 4d 49 4e } //1 .app.action.ADD_DEVICE_ADMIN
		$a_01_2 = {2e 53 43 52 45 45 4e 5f 4f 46 46 } //1 .SCREEN_OFF
		$a_01_3 = {2e 61 6e 64 72 6f 69 64 2e 73 65 74 74 69 6e 67 73 2e 44 65 76 69 63 65 6c 74 41 64 6d 69 6e 41 64 64 } //1 .android.settings.DeviceltAdminAdd
		$a_01_4 = {42 61 69 74 6c 6f 63 6b } //1 Baitlock
		$a_01_5 = {61 74 61 64 20 66 6f 20 74 73 6f 6c 20 65 73 75 61 63 20 64 6e 61 20 73 73 65 63 6f 72 70 20 6e 6f 69 74 61 6c 6c 61 74 73 6e 69 20 74 70 75 72 72 65 74 6e 69 20 6e 61 63 20 75 6f 79 67 71 74 20 4c 45 43 4e 41 43 20 67 6e 69 70 70 61 74 20 79 42 } //1 atad fo tsol esuac dna ssecorp noitallatsni tpurretni nac uoygqt LECNAC gnippat yB
		$a_01_6 = {64 64 41 6e 69 6d 64 41 65 63 69 76 65 44 2e 73 67 5a 71 57 6e 69 74 74 65 73 2e 64 69 6f 72 64 6e 61 2e 6d 6f 63 } //1 ddAnimdAeciveD.sgZqWnittes.diordna.moc
		$a_01_7 = {6b 63 6f 6c 2d 65 63 72 6f 66 } //1 kcol-ecrof
		$a_01_8 = {6d 4f 5a 59 6f 63 2e 6f 73 6f 75 65 6c 62 62 61 62 2f 2f 3a 70 74 74 68 } //1 mOZYoc.osouelbbab//:ptth
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=4
 
}