
rule Trojan_BAT_PassSteal_A_MTB{
	meta:
		description = "Trojan:BAT/PassSteal.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2f 63 72 65 61 74 65 20 2f 73 63 20 4d 49 4e 55 54 45 20 2f 6d 6f 20 31 30 20 2f 74 6e 20 22 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 20 55 70 64 61 74 65 20 53 79 73 74 65 6d 20 46 6f 6c 64 65 72 22 20 2f 74 72 20 22 } //1 /create /sc MINUTE /mo 10 /tn "Windows Defender Update System Folder" /tr "
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 69 70 6c 6f 67 67 65 72 2e 6f 72 67 2f } //1 https://iplogger.org/
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f } //1 https://pastebin.com/raw/
		$a_81_3 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 66 65 72 20 4c 6f 67 67 65 72 20 46 69 6c 65 2e 65 78 65 } //1 Windows Defenfer Logger File.exe
		$a_81_4 = {51 58 42 77 52 47 46 30 59 51 3d 3d } //1 QXBwRGF0YQ==
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}