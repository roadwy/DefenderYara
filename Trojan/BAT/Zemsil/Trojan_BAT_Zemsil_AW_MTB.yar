
rule Trojan_BAT_Zemsil_AW_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 00 50 00 2e 00 65 00 78 00 65 00 } //1 HP.exe
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 43 3a } //1 powershell -Command Add-MpPreference -ExclusionPath C:
		$a_01_2 = {4f 62 66 75 73 63 61 74 6f 72 41 49 4f 20 2d 20 68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 31 32 33 53 74 75 64 69 6f 73 } //1 ObfuscatorAIO - https://github.com/123Studios
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}