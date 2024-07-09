
rule Backdoor_BAT_Sposa_KA_MTB{
	meta:
		description = "Backdoor:BAT/Sposa.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 10 11 11 91 13 12 08 11 12 6f ?? 00 00 0a 00 11 11 17 58 13 11 11 11 11 10 8e 69 32 e2 } //10
		$a_01_1 = {43 6f 6e 76 65 72 74 54 6f 53 68 65 6c 6c 63 6f 64 65 } //1 ConvertToShellcode
		$a_01_2 = {53 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 52 00 44 00 49 00 5f 00 78 00 36 00 34 00 2e 00 62 00 69 00 6e 00 } //1 ShellcodeRDI_x64.bin
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}