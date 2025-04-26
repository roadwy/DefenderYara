
rule Trojan_MacOS_Yontoo_A{
	meta:
		description = "Trojan:MacOS/Yontoo.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {64 61 74 61 2e 64 6f 77 6e 6c 6f 61 64 73 74 61 72 74 65 72 2e 6e 65 74 2f 70 69 6e 67 6d 61 63 2e 61 73 70 } //1 data.downloadstarter.net/pingmac.asp
		$a_00_1 = {2f 43 6f 6e 74 65 6e 74 73 2f 52 65 73 6f 75 72 63 65 73 2f 53 70 6f 72 74 48 75 6e 74 65 72 54 56 41 70 70 2e 61 70 70 } //1 /Contents/Resources/SportHunterTVApp.app
		$a_00_2 = {2f 70 72 69 76 61 74 65 2f 76 61 72 2f 74 6d 70 2f 59 6f 6e 74 6f 6f 4d 61 63 53 69 6c 65 6e 74 49 6e 73 74 61 6c 6c 65 72 } //1 /private/var/tmp/YontooMacSilentInstaller
		$a_00_3 = {2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 59 6f 6e 74 6f 6f 20 49 6e 73 74 61 6c 6c 65 72 20 53 69 6c 65 6e 74 2e 61 70 70 2f 43 6f 6e 74 65 6e 74 73 2f 4d 61 63 4f 53 2f 59 6f 6e 74 6f 6f } //1 /Applications/Yontoo Installer Silent.app/Contents/MacOS/Yontoo
		$a_00_4 = {77 77 77 2e 79 6f 6e 74 6f 6f 2e 63 6f 6d 2f 50 72 69 76 61 63 79 50 6f 6c 69 63 79 2e 61 73 70 78 } //1 www.yontoo.com/PrivacyPolicy.aspx
		$a_00_5 = {ff 15 38 60 02 00 48 31 8d 35 41 60 02 00 4c 89 e7 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*2) >=5
 
}