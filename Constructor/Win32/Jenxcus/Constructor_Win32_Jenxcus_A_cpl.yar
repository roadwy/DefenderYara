
rule Constructor_Win32_Jenxcus_A_cpl{
	meta:
		description = "Constructor:Win32/Jenxcus.A!cpl,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 08 00 00 "
		
	strings :
		$a_01_0 = {6e 6a 77 6f 72 6d 63 6f 6e 74 72 6f 6c 63 65 6e 74 72 65 } //1 njwormcontrolcentre
		$a_01_1 = {62 75 69 6c 64 6e 65 77 77 6f 72 6d } //1 buildnewworm
		$a_01_2 = {77 6f 72 6d 73 65 72 76 65 72 63 6d 64 67 65 74 } //1 wormservercmdget
		$a_01_3 = {77 6f 72 6d 63 6f 64 65 } //1 wormcode
		$a_01_4 = {77 77 77 2e 68 6f 75 64 69 6e 69 73 63 2e 77 69 78 2e 63 6f 6d 2f 70 72 69 76 61 74 65 } //3 www.houdinisc.wix.com/private
		$a_01_5 = {68 6f 75 64 69 6e 69 20 28 63 29 } //3 houdini (c)
		$a_01_6 = {63 6f 6e 74 72 6f 6c 65 72 } //1 controler
		$a_01_7 = {64 65 6c 70 68 69 } //1 delphi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=100
 
}