
rule Trojan_BAT_VenomRAT_SIS_MTB{
	meta:
		description = "Trojan:BAT/VenomRAT.SIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 65 6e 6f 6d 20 52 41 54 20 2b 20 48 56 4e 43 20 2b 20 53 74 65 61 6c 65 72 20 2b 20 47 72 61 62 62 65 72 2e 65 78 65 2e 6c 69 63 65 6e 73 65 73 } //2 Venom RAT + HVNC + Stealer + Grabber.exe.licenses
		$a_01_1 = {56 65 6e 6f 6d 52 41 54 4d 75 74 65 78 5f 56 65 6e 6f 6d 52 41 54 } //2 VenomRATMutex_VenomRAT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}