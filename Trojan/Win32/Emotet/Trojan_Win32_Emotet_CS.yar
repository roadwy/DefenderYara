
rule Trojan_Win32_Emotet_CS{
	meta:
		description = "Trojan:Win32/Emotet.CS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 38 37 32 33 5f 39 32 33 34 36 5f 32 33 39 34 5f 46 46 46 41 } //1 28723_92346_2394_FFFA
		$a_01_1 = {5a 6f 6d 62 69 66 79 41 63 74 43 74 78 } //1 ZombifyActCtx
		$a_01_2 = {6c 76 64 2a 30 6a 3f 23 46 67 } //1 lvd*0j?#Fg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}