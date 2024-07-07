
rule Trojan_BAT_ShellInject_NEAA_MTB{
	meta:
		description = "Trojan:BAT/ShellInject.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 01 00 00 01 0a 16 0b 38 13 00 00 00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 } //7
		$a_01_1 = {2f 00 43 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 20 00 65 00 78 00 65 00 3b 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 20 00 64 00 6c 00 6c 00 } //3 /C powershell.exe Add-MpPreference -ExclusionExtension exe; powershell.exe Add-MpPreference -ExclusionExtension dll
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*3) >=10
 
}