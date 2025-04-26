
rule Trojan_BAT_SpyStealer_AM_MTB{
	meta:
		description = "Trojan:BAT/SpyStealer.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {70 00 61 00 6e 00 65 00 6c 00 73 00 73 00 2e 00 78 00 79 00 7a 00 2f 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 2f 00 54 00 53 00 61 00 76 00 65 00 } //1 panelss.xyz/Stealer/TSave
		$a_01_1 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 5f 00 6b 00 65 00 79 00 } //1 encrypted_key
		$a_01_2 = {76 00 6d 00 77 00 61 00 72 00 65 00 } //1 vmware
		$a_01_3 = {50 00 4b 00 31 00 31 00 53 00 44 00 52 00 5f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 } //1 PK11SDR_Decrypt
		$a_01_4 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 } //1 VirtualBox
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}