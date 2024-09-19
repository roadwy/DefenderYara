
rule Trojan_Win32_VBKlog_EM_MTB{
	meta:
		description = "Trojan:Win32/VBKlog.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 AntiVirusDisableNotify
		$a_81_1 = {46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 FirewallDisableNotify
		$a_81_2 = {55 70 64 61 74 65 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 UpdatesDisableNotify
		$a_81_3 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 64 69 73 61 62 6c 65 } //1 netsh firewall set opmode disable
		$a_81_4 = {43 4c 49 50 42 4f 41 52 44 20 43 48 41 4e 47 45 44 } //1 CLIPBOARD CHANGED
		$a_81_5 = {46 75 63 6b 59 6f 75 72 53 65 6c 66 } //1 FuckYourSelf
		$a_81_6 = {6b 65 79 6c 6f 67 67 65 72 20 2d 20 46 54 50 20 2d 20 62 65 64 75 6e 65 20 65 72 72 6f 72 20 2d 20 52 65 76 69 73 69 6f 6e 31 5c 77 69 6e 6c 6f 67 6f 6e 2e 76 62 70 } //1 keylogger - FTP - bedune error - Revision1\winlogon.vbp
		$a_81_7 = {70 72 6f 6a 65 20 63 6f 64 20 69 6e 6a 65 63 74 6f 72 5f 6e 65 77 20 6d 65 74 68 6f 64 5c 45 78 74 72 61 63 74 65 72 5c 53 74 61 6e 64 61 72 64 2e 76 62 70 } //1 proje cod injector_new method\Extracter\Standard.vbp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}