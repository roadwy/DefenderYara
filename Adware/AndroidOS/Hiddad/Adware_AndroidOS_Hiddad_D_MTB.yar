
rule Adware_AndroidOS_Hiddad_D_MTB{
	meta:
		description = "Adware:AndroidOS/Hiddad.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 54 68 65 4a 6f 62 43 68 72 6f 6d 69 75 6d } //2 /TheJobChromium
		$a_01_1 = {2f 54 68 65 4a 6f 62 53 69 6e 67 6c 65 74 6f 6e } //1 /TheJobSingleton
		$a_01_2 = {73 74 61 72 74 54 68 65 42 72 6f 77 73 65 72 } //1 startTheBrowser
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}