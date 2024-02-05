
rule PWS_Win32_ISR_GG_MTB{
	meta:
		description = "PWS:Win32/ISR.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0d 00 00 01 00 "
		
	strings :
		$a_80_0 = {3f 61 63 74 69 6f 6e 3d 61 64 64 26 75 73 65 72 6e 61 6d 65 3d } //?action=add&username=  01 00 
		$a_80_1 = {6a 44 6f 77 6e 6c 6f 61 64 65 72 } //jDownloader  01 00 
		$a_80_2 = {26 70 61 73 73 77 6f 72 64 3d } //&password=  01 00 
		$a_80_3 = {26 61 70 70 3d } //&app=  01 00 
		$a_80_4 = {26 70 63 6e 61 6d 65 3d } //&pcname=  01 00 
		$a_80_5 = {26 73 69 74 65 6e 61 6d 65 3d } //&sitename=  01 00 
		$a_80_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  01 00 
		$a_80_7 = {3c 53 65 72 76 65 72 3e } //<Server>  01 00 
		$a_80_8 = {3c 50 61 73 73 3e } //<Pass>  01 00 
		$a_80_9 = {49 6e 6a 50 45 } //InjPE  01 00 
		$a_80_10 = {45 6e 63 50 61 73 73 77 6f 72 64 } //EncPassword  01 00 
		$a_80_11 = {54 72 69 6c 6c 69 61 6e } //Trillian  01 00 
		$a_80_12 = {5c 2e 70 75 72 70 6c 65 5c 61 63 63 6f 75 6e 74 73 2e 78 6d 6c } //\.purple\accounts.xml  00 00 
	condition:
		any of ($a_*)
 
}