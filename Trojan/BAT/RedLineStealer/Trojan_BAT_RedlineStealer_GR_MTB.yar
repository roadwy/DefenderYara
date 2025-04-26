
rule Trojan_BAT_RedlineStealer_GR_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {74 69 6e 79 2e 6f 6e 65 2f 63 79 61 37 64 6d 73 75 } //tiny.one/cya7dmsu  1
		$a_80_1 = {50 6f 72 74 61 62 6c 65 41 70 70 73 2e 63 6f 6d } //PortableApps.com  1
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_3 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_80_5 = {45 62 75 7a 63 7a 6b 69 70 77 62 65 64 77 66 } //Ebuzczkipwbedwf  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}