
rule Trojan_BAT_Vidar_NEAB_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 11 0d 16 11 0b 6f cb 00 00 0a 26 11 0a 11 0d 16 11 0b 11 0c 16 6f e3 00 00 0a 13 0f 7e 5e 00 00 04 11 0c 16 11 0f 6f cf 00 00 0a 11 0e 11 0b 58 13 0e 11 0e 11 0b 58 6a 06 6f 96 00 00 0a 32 bf } //10
		$a_01_1 = {43 00 68 00 65 00 63 00 6b 00 52 00 65 00 6d 00 6f 00 74 00 65 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 50 00 72 00 65 00 73 00 65 00 6e 00 74 00 } //2 CheckRemoteDebuggerPresent
		$a_01_2 = {50 72 69 6e 74 41 63 74 69 76 61 74 6f 72 } //2 PrintActivator
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}