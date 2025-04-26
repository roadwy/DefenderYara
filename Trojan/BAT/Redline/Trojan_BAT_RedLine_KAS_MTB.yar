
rule Trojan_BAT_RedLine_KAS_MTB{
	meta:
		description = "Trojan:BAT/RedLine.KAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {46 53 75 6d 6d 46 54 6d 41 49 6c 69 50 } //FSummFTmAIliP  1
		$a_80_1 = {45 59 45 6f 51 57 59 47 74 55 } //EYEoQWYGtU  1
		$a_80_2 = {6b 67 46 53 71 6b 63 65 42 69 70 73 } //kgFSqkceBips  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}