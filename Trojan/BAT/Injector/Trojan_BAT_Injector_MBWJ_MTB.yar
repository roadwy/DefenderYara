
rule Trojan_BAT_Injector_MBWJ_MTB{
	meta:
		description = "Trojan:BAT/Injector.MBWJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 69 6d 79 63 75 68 79 6e 61 78 61 65 66 61 6e 61 65 74 61 77 61 65 } //2 Pimycuhynaxaefanaetawae
		$a_01_1 = {57 79 71 69 6a 75 6d 79 6c 79 73 68 65 66 69 73 68 61 65 70 79 6b 79 } //1 Wyqijumylyshefishaepyky
		$a_01_2 = {65 61 66 38 39 62 65 64 2e 52 65 73 6f 75 72 63 65 73 } //1 eaf89bed.Resources
		$a_01_3 = {64 35 65 39 64 35 64 30 61 33 34 64 } //1 d5e9d5d0a34d
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}