
rule VirTool_BAT_CryptInject_MTB{
	meta:
		description = "VirTool:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {d0 0e 00 00 01 28 ?? 00 00 0a 72 ?? ?? ?? 70 17 fe 0e 03 00 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 40 10 00 00 00 20 02 00 00 00 fe 0e 03 00 fe ?? ?? 00 00 01 58 00 8d 01 00 00 01 0b 07 16 fe 0e 04 00 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 40 ?? 00 00 00 20 ?? 00 00 00 fe 0e 04 00 fe ?? ?? 00 00 01 58 } //1
		$a_02_1 = {d0 0e 00 00 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 17 8d 01 00 00 01 0b 07 16 28 ?? 00 00 06 28 ?? 00 00 0a a2 07 28 ?? 00 00 06 75 ?? 00 00 01 0a d0 ?? 00 00 02 28 ?? 00 00 0a 72 ?? ?? ?? 70 17 8d 01 00 00 01 0c 08 16 06 a2 08 28 0e 00 00 06 26 2a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule VirTool_BAT_CryptInject_MTB_2{
	meta:
		description = "VirTool:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 66 75 63 6b 2e 65 78 65 } //1 .fuck.exe
		$a_01_1 = {49 00 6e 00 6a 00 65 00 63 00 74 00 } //1 Inject
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}