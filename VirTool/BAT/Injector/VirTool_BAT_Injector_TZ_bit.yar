
rule VirTool_BAT_Injector_TZ_bit{
	meta:
		description = "VirTool:BAT/Injector.TZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b7 17 da 09 da 03 09 91 08 61 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 09 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 8e b7 5d 91 61 9c 09 17 d6 0d 09 11 04 } //1
		$a_01_1 = {00 72 70 2e 64 6c 6c 00 } //1
		$a_01_2 = {00 42 6c 6f 63 6b 43 6f 70 79 00 47 65 74 50 72 6f 63 65 73 73 42 79 49 64 00 4b 69 6c 6c } //1 䈀潬正潃祰䜀瑥牐捯獥䉳䥹d楋汬
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}