
rule Trojan_Win32_Qbot_GID_MTB{
	meta:
		description = "Trojan:Win32/Qbot.GID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 5a 31 34 4b 49 54 45 4d 56 49 45 57 53 5f 4c 4f 47 76 } //1 RZ14KITEMVIEWS_LOGv
		$a_01_1 = {52 6e 6d 5f 5f 5f 5a 4e 31 36 51 43 6f 72 65 41 70 70 6c 69 63 61 74 69 6f 6e 34 73 65 6c 66 45 } //1 Rnm___ZN16QCoreApplication4selfE
		$a_01_2 = {52 5a 4e 35 51 48 61 73 68 49 32 31 51 50 65 72 73 69 73 74 65 6e 74 4d 6f 64 65 6c 49 6e 64 65 78 35 51 4c 69 73 74 49 50 37 51 57 69 64 67 65 74 45 45 36 72 65 6d 6f 76 65 45 52 4b 53 30 5f } //1 RZN5QHashI21QPersistentModelIndex5QListIP7QWidgetEE6removeERKS0_
		$a_01_3 = {52 5a 4e 35 51 4c 69 73 74 49 4e 36 51 45 76 65 6e 74 34 54 79 70 65 45 45 43 31 45 52 4b 53 32 5f } //1 RZN5QListIN6QEvent4TypeEEC1ERKS2_
		$a_01_4 = {50 37 51 57 69 64 67 65 74 45 36 72 65 6d 6f 76 65 45 52 4b 53 30 5f } //1 P7QWidgetE6removeERKS0_
		$a_01_5 = {52 5a 4e 35 51 4c 69 73 74 49 50 37 51 57 69 64 67 65 74 45 43 31 45 52 4b 53 32 5f } //1 RZN5QListIP7QWidgetEC1ERKS2_
		$a_01_6 = {52 5a 4e 4b 35 51 48 61 73 68 49 37 51 53 74 72 69 6e 67 4e 31 36 4b 43 61 74 65 67 6f 72 69 7a 65 64 56 69 65 77 37 50 72 69 76 61 74 65 35 42 6c 6f 63 6b 45 45 36 76 61 6c 75 65 73 45 76 } //1 RZNK5QHashI7QStringN16KCategorizedView7Private5BlockEE6valuesEv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}