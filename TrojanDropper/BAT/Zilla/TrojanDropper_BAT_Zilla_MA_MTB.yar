
rule TrojanDropper_BAT_Zilla_MA_MTB{
	meta:
		description = "TrojanDropper:BAT/Zilla.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 02 6f 12 00 00 0a 0c de 0a } //1
		$a_01_1 = {73 74 61 67 65 32 2e 65 78 65 } //1 stage2.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}