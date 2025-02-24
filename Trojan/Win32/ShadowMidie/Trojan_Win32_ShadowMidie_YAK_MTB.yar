
rule Trojan_Win32_ShadowMidie_YAK_MTB{
	meta:
		description = "Trojan:Win32/ShadowMidie.YAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 7d 0c 01 75 05 e8 1f 14 00 00 ff 75 08 } //1
		$a_01_1 = {4e 45 4c 00 33 32 00 00 56 69 72 74 00 00 00 00 75 61 6c 00 50 72 6f 74 00 00 00 00 65 63 74 00 } //10
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=12
 
}