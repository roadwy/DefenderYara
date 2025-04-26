
rule Trojan_BAT_Tnega_PAG_MTB{
	meta:
		description = "Trojan:BAT/Tnega.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 37 41 41 41 41 41 41 41 41 41 41 41 41 41 41 } //2 \7AAAAAAAAAAAAAA
		$a_80_1 = {53 6c 65 65 70 } //Sleep  1
		$a_80_2 = {70 2c 6f 2c 77 65 2c 72 73 2c 68 65 2c 6c 6c } //p,o,we,rs,he,ll  1
		$a_80_3 = {46 72 6f 40 6d 42 61 40 73 65 36 40 34 53 74 40 72 69 6e 67 40 } //Fro@mBa@se6@4St@ring@  1
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}