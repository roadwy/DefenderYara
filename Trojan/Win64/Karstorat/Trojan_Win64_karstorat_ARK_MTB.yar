
rule Trojan_Win64_karstorat_ARK_MTB{
	meta:
		description = "Trojan:Win64/karstorat.ARK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {52 4f 54 41 54 45 5f 4f 4e } //1 ROTATE_ON
		$a_01_1 = {52 4f 54 41 54 45 5f 4f 46 46 } //1 ROTATE_OFF
		$a_01_2 = {4d 4f 55 53 45 5f 53 57 41 50 } //1 MOUSE_SWAP
		$a_01_3 = {4d 4f 55 53 45 5f 52 45 53 54 4f 52 45 } //1 MOUSE_RESTORE
		$a_01_4 = {43 4c 49 50 42 4f 41 52 44 5f 4f 4e } //1 CLIPBOARD_ON
		$a_01_5 = {43 4c 49 50 42 4f 41 52 44 5f 4f 46 46 } //1 CLIPBOARD_OFF
		$a_01_6 = {53 45 4c 46 5f 44 45 53 54 52 55 43 54 } //1 SELF_DESTRUCT
		$a_01_7 = {55 41 43 5f 42 59 50 41 53 53 } //1 UAC_BYPASS
		$a_01_8 = {44 4f 57 4e 4c 4f 41 44 5f 52 55 4e } //1 DOWNLOAD_RUN
		$a_01_9 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41 } //1 capCreateCaptureWindowA
		$a_01_10 = {32 31 32 2e 32 32 37 2e 36 35 2e 31 33 32 } //5 212.227.65.132
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*5) >=15
 
}