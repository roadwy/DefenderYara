
rule Trojan_BAT_AgentTesla_NAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 56 64 47 47 75 7a 71 49 4b 4c 57 6b 68 62 61 7a 6f 68 75 70 73 59 47 54 51 4a } //01 00  TVdGGuzqIKLWkhbazohupsYGTQJ
		$a_01_1 = {69 73 66 64 30 73 64 2e 65 78 65 } //01 00  isfd0sd.exe
		$a_01_2 = {57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  WebResponse
		$a_01_3 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //01 00  System.Runtime.InteropServices
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_6 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //01 00  WriteAllBytes
		$a_01_7 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_8 = {53 79 73 74 65 6d 2e 54 65 78 74 } //01 00  System.Text
		$a_01_9 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_10 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00  HttpWebRequest
		$a_01_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}