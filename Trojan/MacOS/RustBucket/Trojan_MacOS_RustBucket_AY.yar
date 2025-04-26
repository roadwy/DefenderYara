
rule Trojan_MacOS_RustBucket_AY{
	meta:
		description = "Trojan:MacOS/RustBucket.AY,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 6d 73 69 65 20 38 2e 30 3b 20 77 69 6e 64 6f 77 73 20 6e 74 20 36 2e 31 3b 20 74 72 69 64 65 6e 74 2f 34 2e 30 29 } //1 Mozilla/5.0 (compatible; msie 8.0; windows nt 6.1; trident/4.0)
		$a_00_1 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 54 72 69 64 65 6e 74 2f 34 2e 30 29 } //1 Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)
		$a_00_2 = {63 6f 6d 2e 61 70 70 6c 65 2e 73 79 73 74 65 6d 75 70 64 61 74 65 2e 70 6c 69 73 74 } //3 com.apple.systemupdate.plist
		$a_00_3 = {2f 4c 69 62 72 61 72 79 2f 4d 65 74 61 64 61 74 61 2f 53 79 73 74 65 6d 20 55 70 64 61 74 65 } //2 /Library/Metadata/System Update
		$a_00_4 = {63 6f 6d 2e 61 70 70 6c 65 2e 73 61 66 61 72 69 75 70 64 61 74 65 2e 70 6c 69 73 74 } //3 com.apple.safariupdate.plist
		$a_00_5 = {4c 69 62 72 61 72 79 2f 41 70 70 6c 69 63 61 74 69 6f 6e 20 53 75 70 70 6f 72 74 2f 53 61 66 61 72 69 20 55 70 64 61 74 65 } //2 Library/Application Support/Safari Update
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*3+(#a_00_3  & 1)*2+(#a_00_4  & 1)*3+(#a_00_5  & 1)*2) >=6
 
}