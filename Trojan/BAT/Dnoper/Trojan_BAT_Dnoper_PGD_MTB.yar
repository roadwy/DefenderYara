
rule Trojan_BAT_Dnoper_PGD_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.PGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {31 30 33 2e 31 37 39 2e 31 38 34 2e 31 35 36 2f 53 54 43 2f 63 6f 6e 66 69 67 2e 6a 73 6f 6e } //103.179.184.156/STC/config.json  1
		$a_80_1 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //Microsoft\Windows\Start Menu\Programs\Startup  2
		$a_80_2 = {50 44 46 20 64 6f 77 6e 6c 6f 61 64 65 64 20 61 6e 64 20 73 61 76 65 64 20 74 6f 3a } //PDF downloaded and saved to:  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=5
 
}