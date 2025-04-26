
rule Trojan_BAT_Vidar_AYA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 23 00 00 00 00 00 00 00 00 0a 16 0b 2b 19 00 06 07 6c 23 00 00 00 00 00 00 00 40 28 4e 00 00 0a 58 0a 00 07 17 58 0b 07 20 40 42 0f 00 fe 04 0c 08 2d db 1f 64 28 28 00 00 0a 00 00 17 0d 2b bf } //2
		$a_00_1 = {4e 00 6f 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 20 00 2d 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 50 00 6f 00 6c 00 69 00 63 00 79 00 20 00 42 00 79 00 70 00 61 00 73 00 73 00 20 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 NoProfile -ExecutionPolicy Bypass -Command
		$a_01_2 = {49 73 52 75 6e 41 73 41 64 6d 69 6e } //1 IsRunAsAdmin
		$a_01_3 = {52 65 73 74 61 72 74 41 73 41 64 6d 69 6e } //1 RestartAsAdmin
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}