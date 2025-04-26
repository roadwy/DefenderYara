
rule Trojan_BAT_Artel_AB_MTB{
	meta:
		description = "Trojan:BAT/Artel.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 00 65 00 6c 00 6c 00 6f 00 20 00 46 00 72 00 6f 00 6d 00 20 00 4d 00 61 00 69 00 6e 00 2e 00 2e 00 2e 00 49 00 20 00 44 00 6f 00 6e 00 27 00 74 00 20 00 44 00 6f 00 20 00 41 00 6e 00 79 00 74 00 68 00 69 00 6e 00 67 00 } //1 Hello From Main...I Don't Do Anything
		$a_01_1 = {49 00 20 00 73 00 68 00 6f 00 75 00 6c 00 64 00 6e 00 27 00 74 00 20 00 72 00 65 00 61 00 6c 00 6c 00 79 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 } //1 I shouldn't really execute
		$a_01_2 = {5c 41 6c 6c 54 68 65 54 68 69 6e 67 73 2e 64 6c 6c } //1 \AllTheThings.dll
		$a_01_3 = {64 6c 6c 67 75 65 73 74 2e 42 79 70 61 73 73 } //1 dllguest.Bypass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}