
rule Trojan_BAT_RedLineStealer_EH_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 00 78 00 63 00 54 00 45 00 44 00 30 00 39 00 4e 00 68 00 41 00 39 00 4c 00 77 00 6f 00 46 00 4b 00 79 00 59 00 77 00 52 00 53 00 67 00 6e 00 4c 00 68 00 6f 00 } //1 CxcTED09NhA9LwoFKyYwRSgnLho
		$a_01_1 = {4a 00 79 00 6f 00 32 00 45 00 52 00 45 00 6f 00 54 00 6c 00 67 00 3d 00 } //1 Jyo2EREoTlg=
		$a_01_2 = {6e 00 65 00 74 00 2e 00 74 00 63 00 70 00 3a 00 2f 00 2f 00 } //1 net.tcp://
		$a_01_3 = {6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //1 localhost
		$a_01_4 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 } //1 Confuser.Core
		$a_01_5 = {6f 73 5f 63 72 79 70 74 } //1 os_crypt
		$a_01_6 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Trojan_BAT_RedLineStealer_EH_MTB_2{
	meta:
		description = "Trojan:BAT/RedLineStealer.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 07 6f 2f 00 00 0a 03 07 03 6f 55 00 00 0a 5d 6f 2f 00 00 0a 61 0c 06 72 75 08 00 70 08 28 a0 00 00 0a 6f a1 00 00 0a 26 00 07 17 58 0b 07 02 6f 55 00 00 0a fe 04 0d 09 2d c4 } //5
		$a_01_1 = {42 00 43 00 72 00 68 00 4b 00 65 00 79 00 79 00 70 00 74 00 44 00 65 00 73 00 68 00 4b 00 65 00 79 00 74 00 72 00 6f 00 79 00 4b 00 68 00 4b 00 65 00 79 00 65 00 79 00 } //1 BCrhKeyyptDeshKeytroyKhKeyey
		$a_01_2 = {41 00 70 00 70 00 46 00 69 00 6c 00 65 00 2e 00 57 00 72 00 69 00 74 00 65 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 46 00 69 00 6c 00 65 00 2e 00 57 00 72 00 69 00 74 00 65 00 6e 00 67 00 } //1 AppFile.WriteData\RoamiFile.Writeng
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}