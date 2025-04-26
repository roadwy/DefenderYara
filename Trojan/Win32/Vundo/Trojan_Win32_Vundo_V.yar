
rule Trojan_Win32_Vundo_V{
	meta:
		description = "Trojan:Win32/Vundo.V,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {26 76 3d 25 78 5f 25 78 5f 25 78 5f 25 78 5f 25 73 } //5 &v=%x_%x_%x_%x_%s
		$a_01_1 = {26 61 76 73 3d 25 69 } //5 &avs=%i
		$a_01_2 = {45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 Explorer\ShellExecuteHooks
		$a_01_3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_01_4 = {41 6e 74 69 56 69 72 75 73 } //1 AntiVirus
		$a_01_5 = {4e 6f 72 74 6f 6e 20 } //3 Norton 
		$a_01_6 = {42 69 74 44 65 66 65 6e 64 65 72 } //3 BitDefender
		$a_01_7 = {61 76 61 73 74 21 } //3 avast!
		$a_01_8 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //5 SeDebugPrivilege
		$a_01_9 = {50 72 69 76 61 63 79 53 65 74 5a 6f 6e 65 50 72 65 66 65 72 65 6e 63 65 } //5 PrivacySetZonePreference
		$a_01_10 = {52 74 6c 54 69 6d 65 54 6f 53 65 63 6f 6e 64 73 53 69 6e 63 65 31 39 37 30 } //5 RtlTimeToSecondsSince1970
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5+(#a_01_10  & 1)*5) >=31
 
}