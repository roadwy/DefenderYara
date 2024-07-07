
rule Trojan_Win32_Dridex_SN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {46 43 68 72 6f 6d 65 7a 68 61 73 6b 69 6c 6c 65 72 46 69 72 65 66 6f 78 74 6f 44 52 75 6d 6f 72 73 69 73 } //FChromezhaskillerFirefoxtoDRumorsis  3
		$a_80_1 = {74 32 74 68 65 54 68 65 49 47 6f 6f 67 6c 65 6f 66 61 64 64 72 65 73 73 57 70 6f 72 73 63 68 65 } //t2theTheIGoogleofaddressWporsche  3
		$a_80_2 = {57 33 61 6e 64 32 30 31 31 2c 39 6f 6e 6a 4a 32 30 31 33 2c 32 73 } //W3and2011,9onjJ2013,2s  3
		$a_80_3 = {48 62 63 68 69 63 6b 65 6e 61 64 73 6e 34 79 6c 6f 76 65 72 73 54 68 65 } //Hbchickenadsn4yloversThe  3
		$a_80_4 = {52 70 6b 64 65 72 33 33 36 } //Rpkder336  3
		$a_80_5 = {46 67 76 6d 46 70 6d 2e 70 64 62 } //FgvmFpm.pdb  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}