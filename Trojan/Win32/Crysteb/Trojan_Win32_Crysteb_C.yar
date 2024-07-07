
rule Trojan_Win32_Crysteb_C{
	meta:
		description = "Trojan:Win32/Crysteb.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {70 6b 65 64 63 6a 6b 64 65 66 67 70 64 65 6c 70 62 63 6d 62 6d 65 6f 6d 63 6a 62 65 65 6d 66 6d } //1 pkedcjkdefgpdelpbcmbmeomcjbeemfm
		$a_01_1 = {67 68 62 6d 6e 6e 6a 6f 6f 65 6b 70 6d 6f 65 63 6e 6e 6e 69 6c 6e 6e 62 64 6c 6f 6c 68 6b 68 69 } //1 ghbmnnjooekpmoecnnnilnnbdlolhkhi
		$a_01_2 = {69 6f 62 6b 6c 66 65 70 6a 6f 63 6e 61 6d 67 6b 6b 62 69 67 6c 69 64 6f 6d } //1 iobklfepjocnamgkkbiglidom
		$a_01_3 = {73 63 72 69 70 74 2d 73 72 63 20 27 73 65 6c 66 27 20 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 73 74 61 74 69 63 2e 63 6f 6d 2f 20 68 74 74 70 73 3a 2f 2f 61 63 63 6f 75 6e 74 73 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 20 68 74 74 70 73 3a 2f 2f 2a 2e 66 69 72 65 62 61 73 65 69 6f 2e 63 6f 6d 20 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 61 70 69 73 2e 63 6f 6d 3b 20 6f 62 6a 65 63 74 2d 73 72 63 20 27 73 65 6c 66 27 } //1 script-src 'self' https://www.gstatic.com/ https://accounts.google.com https://*.firebaseio.com https://www.googleapis.com; object-src 'self'
		$a_01_4 = {5c 66 69 72 65 62 61 73 65 2d 6d 65 73 73 61 67 69 6e 67 2e 6a 73 } //1 \firebase-messaging.js
		$a_01_5 = {5c 66 69 72 65 62 61 73 65 2d 6d 65 73 73 61 67 69 6e 67 2d 73 77 2e 6a 73 } //1 \firebase-messaging-sw.js
		$a_01_6 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c } //1 \Mozilla\Firefox\Profiles\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}