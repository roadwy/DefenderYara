
rule Trojan_AndroidOS_Filecoder_C{
	meta:
		description = "Trojan:AndroidOS/Filecoder.C,SIGNATURE_TYPE_DEXHSTR_EXT,0e 00 0e 00 15 00 00 "
		
	strings :
		$a_01_0 = {6c 75 63 6b 79 73 65 76 65 6e } //1 luckyseven
		$a_01_1 = {72 69 63 68 37 2e 78 79 7a } //1 rich7.xyz
		$a_01_2 = {61 66 66 65 63 74 65 64 } //1 affected
		$a_01_3 = {70 61 73 74 65 62 69 6e 2e 63 6f 6d } //1 pastebin.com
		$a_01_4 = {42 69 74 63 6f 69 6e 20 61 64 64 72 65 73 73 20 63 6f 70 79 20 63 6f 6d 70 6c 65 74 65 64 } //1 Bitcoin address copy completed
		$a_01_5 = {73 74 61 72 74 20 73 68 6f 77 20 77 61 72 6e 69 6e 67 } //1 start show warning
		$a_01_6 = {6c 6f 63 6b 69 6e 67 20 66 69 6c 65 } //1 locking file
		$a_01_7 = {6c 6f 63 6b 69 6e 67 20 70 68 6f 74 6f } //1 locking photo
		$a_01_8 = {2e 73 65 76 65 6e } //1 .seven
		$a_01_9 = {4c 6a 61 76 61 2f 6c 61 6e 67 2f 54 68 72 65 61 64 3b } //1 Ljava/lang/Thread;
		$a_01_10 = {4c 6a 61 76 61 2f 6c 61 6e 67 2f 52 75 6e 6e 61 62 6c 65 3b } //1 Ljava/lang/Runnable;
		$a_01_11 = {73 65 6e 64 4d 75 6c 74 69 70 61 72 74 54 65 78 74 4d 65 73 73 61 67 65 } //1 sendMultipartTextMessage
		$a_01_12 = {4c 61 6e 64 72 6f 69 64 2f 74 65 6c 65 70 68 6f 6e 79 2f 53 6d 73 4d 61 6e 61 67 65 72 3b } //1 Landroid/telephony/SmsManager;
		$a_01_13 = {67 65 74 42 74 63 55 72 6c } //1 getBtcUrl
		$a_01_14 = {67 65 74 44 65 63 72 79 70 74 55 72 6c } //1 getDecryptUrl
		$a_01_15 = {67 65 74 50 68 6f 74 6f 50 61 74 68 } //1 getPhotoPath
		$a_01_16 = {67 65 74 49 6e 6e 65 72 53 74 6f 72 61 67 65 50 61 74 68 } //1 getInnerStoragePath
		$a_01_17 = {67 65 74 41 6c 6c 57 6f 72 6b 46 69 6c 65 } //1 getAllWorkFile
		$a_01_18 = {67 65 74 41 6c 6c 55 6e 77 6f 72 6b 46 69 6c 65 } //1 getAllUnworkFile
		$a_01_19 = {67 65 6e 65 72 61 74 65 52 53 41 4b 65 79 50 61 69 72 } //1 generateRSAKeyPair
		$a_01_20 = {65 6e 63 72 79 70 74 42 79 50 75 62 6c 69 63 4b 65 79 46 6f 72 53 70 69 6c 74 } //1 encryptByPublicKeyForSpilt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1) >=14
 
}