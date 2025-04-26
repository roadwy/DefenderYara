
rule Backdoor_Win32_Remcos_A_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 20 74 6f 20 43 26 43 3a } //1 Uploading file to C&C:
		$a_01_1 = {68 00 43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 22 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 22 00 29 00 2e 00 52 00 75 00 6e 00 20 00 22 00 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 22 00 22 00 } //1 hCreateObject("WScript.Shell").Run "cmd /c ""
		$a_01_2 = {52 45 4d 43 4f 53 } //1 REMCOS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}