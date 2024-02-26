
rule Trojan_Win32_GuLoader_ME_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 4f 70 65 72 61 74 6f 72 2e 65 78 65 } //03 00  FileOperator.exe
		$a_81_1 = {4f 44 43 6f 6e 74 72 6f 6c 2e 64 6c 6c } //03 00  ODControl.dll
		$a_81_2 = {4f 70 65 6e 53 53 4c 2d 4c 69 63 65 6e 73 65 2e 74 78 74 } //03 00  OpenSSL-License.txt
		$a_81_3 = {53 65 74 75 70 41 55 52 41 43 72 65 61 74 6f 72 2e 65 78 65 } //03 00  SetupAURACreator.exe
		$a_81_4 = {41 72 67 6f 20 41 49 } //03 00  Argo AI
		$a_81_5 = {44 65 6c 65 74 65 20 6f 6e 20 72 65 62 6f 6f 74 } //00 00  Delete on reboot
	condition:
		any of ($a_*)
 
}