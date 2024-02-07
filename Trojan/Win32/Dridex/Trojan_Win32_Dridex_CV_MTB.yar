
rule Trojan_Win32_Dridex_CV_MTB{
	meta:
		description = "Trojan:Win32/Dridex.CV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {4e 41 72 74 68 65 72 65 52 37 65 76 65 72 79 68 } //01 00  NArthereR7everyh
		$a_81_1 = {69 73 6e 2e 74 2c 66 69 6c 6c 2c 73 65 74 2c 41 6c 69 76 69 6e 67 74 72 65 65 } //01 00  isn.t,fill,set,Alivingtree
		$a_81_2 = {69 73 6e 2e 74 2e 61 69 72 2c 77 68 6f 73 65 48 34 43 63 } //01 00  isn.t.air,whoseH4Cc
		$a_81_3 = {65 55 6e 64 65 72 64 61 72 6b 6e 65 73 73 62 65 6d 65 61 74 74 6f 2e 67 69 76 65 } //01 00  eUnderdarknessbemeatto.give
		$a_81_4 = {43 66 69 73 68 2e 74 68 65 2e 6d 41 50 } //01 00  Cfish.the.mAP
		$a_81_5 = {53 45 54 55 50 41 50 49 2e 64 6c 6c } //01 00  SETUPAPI.dll
		$a_81_6 = {43 6f 44 6f 73 44 61 74 65 54 69 6d 65 54 6f 46 69 6c 65 54 69 6d 65 } //00 00  CoDosDateTimeToFileTime
	condition:
		any of ($a_*)
 
}