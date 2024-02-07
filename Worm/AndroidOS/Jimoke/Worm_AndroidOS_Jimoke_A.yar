
rule Worm_AndroidOS_Jimoke_A{
	meta:
		description = "Worm:AndroidOS/Jimoke.A,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 3a 2f 2f 2f 61 6e 64 72 6f 69 64 5f 61 73 73 65 74 2f 64 64 2e 68 74 6d 6c } //02 00  file:///android_asset/dd.html
		$a_01_1 = {68 74 74 70 3a 2f 2f 74 69 6e 79 2e 63 63 2f 4a 69 6f 50 72 69 6d 65 } //02 00  http://tiny.cc/JioPrime
		$a_00_2 = {4c 63 6f 6d 2f 6d 61 72 6f 6c 65 6d 6f 64 2f 62 6e 63 68 6f 64 6d 64 61 2f 4d 61 69 6e 32 41 63 74 69 76 69 74 79 } //01 00  Lcom/marolemod/bnchodmda/Main2Activity
		$a_01_3 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 53 75 70 65 72 75 73 65 72 2e 61 70 6b } //01 00  /system/app/Superuser.apk
		$a_01_4 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 75 } //01 00  /system/bin/su
		$a_00_5 = {32 30 32 37 38 37 38 35 32 } //02 00  202787852
		$a_01_6 = {61 53 49 53 4b 53 62 68 46 4c 59 45 2f 62 39 44 45 42 53 37 64 30 4d 44 59 73 78 38 77 38 75 45 66 67 46 35 75 71 7a 6a 33 31 39 77 36 4a 4e 62 52 35 32 73 61 48 44 50 44 59 57 45 4c 57 50 57 72 72 5a 5a 71 59 78 5a 44 57 4e 55 2f 72 33 47 34 67 62 45 2b 69 56 6e 79 55 2f 31 4b 62 6f 68 6d 6e 74 4a 50 6d 71 2f 51 2f 74 63 35 4f 4a 55 55 55 4b 37 6c 47 39 57 49 42 75 61 4a 71 55 2f 79 } //02 00  aSISKSbhFLYE/b9DEBS7d0MDYsx8w8uEfgF5uqzj319w6JNbR52saHDPDYWELWPWrrZZqYxZDWNU/r3G4gbE+iVnyU/1KbohmntJPmq/Q/tc5OJUUUK7lG9WIBuaJqU/y
		$a_00_7 = {4c 63 6f 6d 2f 6d 61 72 6f 6c 65 6d 6f 64 2f 62 6e 63 68 6f 64 6d 64 61 2f 6e 65 77 73 65 72 } //00 00  Lcom/marolemod/bnchodmda/newser
	condition:
		any of ($a_*)
 
}