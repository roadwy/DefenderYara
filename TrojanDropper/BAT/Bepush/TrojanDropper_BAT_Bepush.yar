
rule TrojanDropper_BAT_Bepush{
	meta:
		description = "TrojanDropper:BAT/Bepush,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_80_0 = {5c 53 45 78 74 65 6e 73 69 6f 6e } //\SExtension  1
		$a_80_1 = {5c 56 45 78 74 65 6e 73 69 6f 6e } //\VExtension  1
		$a_80_2 = {59 6f 6b 45 78 65 2e 65 78 65 } //YokExe.exe  1
		$a_80_3 = {46 4c 56 47 75 6e 63 65 6c 6c 65 } //FLVGuncelle  1
		$a_80_4 = {46 6c 61 73 68 47 75 6e 63 65 6c 6c 65 } //FlashGuncelle  1
		$a_80_5 = {42 61 6b 42 61 6b 69 6d } //BakBakim  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=2
 
}