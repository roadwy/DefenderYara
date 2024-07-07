
rule Trojan_Win32_Emotetcrypt_FP_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_81_1 = {68 6d 71 63 62 62 69 6e 78 67 64 6b 6e 73 73 63 6c 76 64 2e 64 6c 6c } //1 hmqcbbinxgdknssclvd.dll
		$a_81_2 = {6b 63 6a 6f 79 6d 61 68 71 67 61 69 67 64 63 6b 6f } //1 kcjoymahqgaigdcko
		$a_81_3 = {6b 65 71 6f 76 67 63 6f 73 6b 65 65 70 63 69 69 } //1 keqovgcoskeepcii
		$a_81_4 = {6b 72 7a 72 71 71 6a 65 68 6f 72 79 70 67 74 } //1 krzrqqjehorypgt
		$a_81_5 = {6d 63 79 78 77 6c 62 73 6e 78 68 75 66 61 61 } //1 mcyxwlbsnxhufaa
		$a_81_6 = {64 73 6f 6d 63 6f 63 61 61 65 74 76 66 2e 64 6c 6c } //1 dsomcocaaetvf.dll
		$a_81_7 = {62 6b 71 65 64 79 74 69 68 63 61 66 64 64 76 6e 62 } //1 bkqedytihcafddvnb
		$a_81_8 = {65 6f 64 70 70 73 68 61 74 79 66 65 68 6f 6b 67 65 } //1 eodppshatyfehokge
		$a_81_9 = {68 63 70 6f 74 72 7a 65 75 62 68 6b 6b 76 6e 68 73 } //1 hcpotrzeubhkkvnhs
		$a_81_10 = {6a 6b 63 67 65 74 69 62 61 6c 68 64 77 6d 71 64 } //1 jkcgetibalhdwmqd
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=15
 
}