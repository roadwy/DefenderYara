
rule Trojan_BAT_Bodegun_PGB_MTB{
	meta:
		description = "Trojan:BAT/Bodegun.PGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_80_0 = {48 69 2c 20 69 6d 20 61 20 6d 6f 73 71 75 69 74 6f 2c 20 61 20 6d 6f 73 71 75 69 74 6f 20 74 68 61 74 20 63 75 72 72 65 6e 74 6c 79 20 69 6e 66 65 63 74 65 64 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 2e } //Hi, im a mosquito, a mosquito that currently infected your computer.  1
		$a_80_1 = {77 6f 75 6c 64 20 79 6f 75 20 6c 69 6b 65 20 74 6f 20 73 74 6f 70 20 74 68 65 20 69 6e 66 65 63 74 69 6f 6e 3f } //would you like to stop the infection?  4
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*4) >=5
 
}