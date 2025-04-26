
rule Trojan_Linux_Stiniter_A{
	meta:
		description = "Trojan:Linux/Stiniter.A,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 64 61 74 61 2f 6c 6f 67 2e 74 78 74 } //1 /data/log.txt
		$a_01_1 = {2f 64 61 74 61 2f 72 65 6e 64 } //1 /data/rend
		$a_01_2 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 00 00 2f 00 00 00 70 69 70 65 43 6d 64 3a 3c 25 73 3e } //1
		$a_01_3 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 6b 65 65 70 65 72 } //1 /system/bin/keeper
		$a_01_4 = {72 65 61 64 20 66 64 20 69 73 73 65 74 } //1 read fd isset
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Linux_Stiniter_A_2{
	meta:
		description = "Trojan:Linux/Stiniter.A,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 67 6f 6f 67 6c 65 6d 65 73 73 61 67 65 2e 61 70 6b } //1 /googlemessage.apk
		$a_01_1 = {2f 61 6e 64 72 6f 69 64 2e 69 6e 66 6f } //1 /android.info
		$a_01_2 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 61 6e 64 72 6f 69 64 2e 69 6e 66 6f } //1 /system/bin/android.info
		$a_01_3 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 6b 65 65 70 65 72 } //1 /system/bin/keeper
		$a_01_4 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 74 73 } //1 /system/bin/ts
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Linux_Stiniter_A_3{
	meta:
		description = "Trojan:Linux/Stiniter.A,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 61 74 61 2f 63 6f 6d 2e 67 6f 6f 67 6c 65 2e 75 70 64 61 74 65 73 65 72 76 69 63 65 2f 73 79 73 2e 69 6e 66 6f } //1 data/com.google.updateservice/sys.info
		$a_01_1 = {63 68 6d 6f 64 20 30 37 37 37 20 2f 73 79 73 74 65 6d 2f 65 74 63 00 00 2f 64 61 74 61 2f 67 6f 6f 67 6c 65 73 65 72 76 69 63 65 2e 61 70 6b 00 70 6d 20 69 6e 73 74 61 6c 6c 20 2d 72 } //1
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 5f 75 72 6c 5f 6c 69 73 74 } //1 Download_url_list
		$a_01_3 = {2f 48 65 61 72 74 42 65 61 74 2e 64 6f } //1 /HeartBeat.do
		$a_01_4 = {74 67 6c 6f 61 64 65 72 2d 61 6e 64 72 6f 69 64 } //1 tgloader-android
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}