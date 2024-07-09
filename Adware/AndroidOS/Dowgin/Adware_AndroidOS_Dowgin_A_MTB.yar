
rule Adware_AndroidOS_Dowgin_A_MTB{
	meta:
		description = "Adware:AndroidOS/Dowgin.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 00 31 00 62 00 ?? ?? 13 01 0d 00 71 10 ?? ?? 01 00 0c 01 6e 20 ?? ?? 10 00 62 00 } //1
		$a_01_1 = {6f 6e 53 74 61 72 74 43 6f 6d 6d 61 6e 64 } //1 onStartCommand
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}