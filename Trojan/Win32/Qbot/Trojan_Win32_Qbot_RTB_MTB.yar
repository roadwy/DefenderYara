
rule Trojan_Win32_Qbot_RTB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  1
		$a_80_1 = {46 78 65 53 52 6b 56 71 6f 5a 4f 64 63 73 } //FxeSRkVqoZOdcs  1
		$a_80_2 = {4f 4c 58 67 76 66 6e 64 4d } //OLXgvfndM  1
		$a_80_3 = {55 76 44 4f 6f 73 51 61 69 50 70 } //UvDOosQaiPp  1
		$a_80_4 = {59 59 4d 6f 5a 65 65 6a 74 69 57 55 } //YYMoZeejtiWU  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}