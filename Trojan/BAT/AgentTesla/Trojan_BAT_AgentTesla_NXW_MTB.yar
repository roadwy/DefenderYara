
rule Trojan_BAT_AgentTesla_NXW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {57 ff a2 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 99 00 00 00 70 00 00 00 7a 02 00 00 af 04 00 00 7c 02 00 00 0a 00 00 00 86 01 00 00 bf } //03 00 
		$a_01_1 = {49 6f 6e 69 63 2e 5a 69 70 } //03 00  Ionic.Zip
		$a_01_2 = {62 75 69 6c 64 2e 65 78 65 } //01 00  build.exe
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //00 00  DownloadString
	condition:
		any of ($a_*)
 
}