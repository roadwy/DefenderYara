
rule Trojan_BAT_CryptInject_MBJS_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 35 42 33 32 46 46 45 37 2d 31 39 38 43 2d 34 43 38 43 2d 42 46 33 34 2d 30 42 39 42 45 38 45 38 30 37 45 45 } //1 $5B32FFE7-198C-4C8C-BF34-0B9BE8E807EE
		$a_01_1 = {53 6c 69 6e 67 2e 64 6c 6c } //1 Sling.dll
		$a_01_2 = {53 6c 69 6e 67 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 Sling.g.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}