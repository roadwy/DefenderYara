
rule TrojanSpy_Win32_BBSwift_A{
	meta:
		description = "TrojanSpy:Win32/BBSwift.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 74 6f 20 63 6f 6e 74 72 6f 6c 20 70 72 69 6e 74 65 72 2e 20 63 6d 64 3d 25 64 2c 20 65 72 72 3d 25 64 } //2 Failed to control printer. cmd=%d, err=%d
		$a_01_1 = {44 45 4c 45 54 45 20 46 52 4f 4d 20 53 41 41 4f 57 4e 45 52 2e 54 45 58 54 5f 25 73 20 57 48 45 52 45 20 54 45 58 54 5f 53 5f 55 4d 49 44 } //2 DELETE FROM SAAOWNER.TEXT_%s WHERE TEXT_S_UMID
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 65 6e 75 6d 6a 6f 62 73 2e 20 65 72 72 3d 25 64 } //2 Failed to enumjobs. err=%d
		$a_01_3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 28 53 45 4c 45 43 54 20 4a 52 4e 4c 5f 44 49 53 50 4c 41 59 5f 54 45 58 54 2c 20 4a 52 4e 4c 5f 44 41 54 45 5f 54 49 4d 45 20 46 52 4f 4d 20 53 41 41 4f 57 4e 45 52 2e 4a 52 4e 4c 5f 25 73 20 57 48 45 52 45 20 4a 52 4e 4c 5f 44 49 53 50 4c 41 59 5f 54 45 58 54 } //2 SELECT * FROM (SELECT JRNL_DISPLAY_TEXT, JRNL_DATE_TIME FROM SAAOWNER.JRNL_%s WHERE JRNL_DISPLAY_TEXT
		$a_01_4 = {3a 25 73 3a 25 63 25 73 25 2e 32 64 25 73 25 73 25 73 } //1 :%s:%c%s%.2d%s%s%s
		$a_01_5 = {43 46 47 20 4f 4b 28 25 73 29 } //1 CFG OK(%s)
		$a_01_6 = {46 45 44 45 52 41 4c 20 52 45 53 45 52 56 45 20 42 41 4e 4b 00 } //1
		$a_01_7 = {65 63 68 6f 20 65 78 69 74 20 7c 20 22 25 73 22 20 2d 53 20 2f 20 61 73 20 73 79 73 64 62 61 20 40 25 73 20 3e } //1 echo exit | "%s" -S / as sysdba @%s >
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=9
 
}