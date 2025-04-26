
rule VirTool_BAT_Injector_GC{
	meta:
		description = "VirTool:BAT/Injector.GC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 25 0a 19 5e 45 03 00 00 00 e0 ff ff ff 02 00 00 00 12 00 00 00 2b 10 00 06 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 61 2b d3 } //1
		$a_00_1 = {23 00 34 00 3d 00 7e 00 71 00 34 00 69 00 42 00 62 00 51 00 7d 00 5c 00 5d 00 5c 00 5d 00 20 00 33 00 51 00 60 00 51 00 6d 00 5c 00 5b 00 72 00 68 00 5c 00 2a 00 3f 00 25 00 } //1 #4=~q4iBbQ}\]\] 3Q`Qm\[rh\*?%
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}