
rule Trojan_Win64_Truebot_ZG_MTB{
	meta:
		description = "Trojan:Win64/Truebot.ZG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 75 73 65 72 5c 44 6f 63 75 6d 65 6e 74 73 5c 50 72 6f 6a 65 63 74 5c 63 68 65 63 6b 5f 6e 61 6d 65 5c 74 61 72 67 65 74 5c 72 65 6c 65 61 73 65 5c 64 65 70 73 5c 46 69 6e 67 65 72 50 72 69 6e 74 5f 64 69 73 61 62 6c 65 2e 70 64 62 } //1 C:\Users\user\Documents\Project\check_name\target\release\deps\FingerPrint_disable.pdb
		$a_01_1 = {51 00 74 00 57 00 65 00 62 00 45 00 6e 00 67 00 69 00 6e 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //1 QtWebEngineProcess.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}