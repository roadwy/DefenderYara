
rule Trojan_BAT_AveMaria_NEBA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 7e 03 00 00 04 11 07 7e 03 00 00 04 11 07 91 20 ca 02 00 00 59 d2 9c 00 11 07 17 58 13 07 11 07 7e 03 00 00 04 8e 69 fe 04 13 08 11 08 2d d0 } //5
		$a_01_1 = {66 00 69 00 6c 00 65 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 69 00 6f 00 2f 00 64 00 61 00 74 00 61 00 2d 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 2f 00 33 00 31 00 4b 00 67 00 36 00 6b 00 63 00 45 00 } //2 filetransfer.io/data-package/31Kg6kcE
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}