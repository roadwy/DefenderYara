
rule Trojan_Win32_Emotet_RA{
	meta:
		description = "Trojan:Win32/Emotet.RA,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {23 48 45 4a 65 52 54 45 24 33 23 40 2e 70 64 62 } //1 #HEJeRTE$3#@.pdb
		$a_01_1 = {63 00 6c 00 69 00 65 00 6e 00 74 00 49 00 44 00 31 00 31 00 31 00 61 00 34 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 63 00 6f 00 6f 00 72 00 64 00 69 00 6e 00 61 00 74 00 65 00 64 00 54 00 68 00 65 00 6f 00 74 00 68 00 65 00 72 00 4f 00 70 00 6c 00 75 00 67 00 2d 00 69 00 6e 00 73 00 59 00 } //1 clientID111a4zzzzzzcoordinatedTheotherOplug-insY
		$a_01_2 = {61 00 6d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 58 00 77 00 6f 00 72 00 6b 00 61 00 72 00 6f 00 75 00 6e 00 64 00 73 00 32 00 61 00 6c 00 6f 00 6e 00 67 00 6e 00 4c 00 71 00 } //1 amanagementXworkarounds2alongnLq
		$a_01_3 = {62 00 6f 00 6e 00 6e 00 69 00 65 00 63 00 6f 00 6d 00 70 00 65 00 74 00 69 00 74 00 6f 00 72 00 73 00 66 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 65 00 61 00 67 00 6c 00 65 00 31 00 61 00 73 00 } //1 bonniecompetitorsfextensionseagle1as
		$a_01_4 = {72 00 65 00 6c 00 65 00 61 00 73 00 65 00 69 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 62 00 65 00 6e 00 6a 00 61 00 6d 00 69 00 6e 00 52 00 61 00 73 00 34 00 39 00 63 00 75 00 70 00 64 00 61 00 74 00 65 00 73 00 2e 00 39 00 32 00 } //1 releaseinstancebenjaminRas49cupdates.92
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}