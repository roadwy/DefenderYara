
rule Trojan_BAT_Lazy_AMTB{
	meta:
		description = "Trojan:BAT/Lazy!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 61 74 5f 74 65 6d 70 5f } //rat_temp_  1
		$a_80_1 = {5b 49 4e 46 4f 5d 20 52 41 54 20 63 6c 69 65 6e 74 20 69 73 20 77 6f 72 6b 69 6e 67 21 } //[INFO] RAT client is working!  1
		$a_80_2 = {41 63 68 65 72 6f 6e 58 5f 43 6c 69 65 6e 74 } //AcheronX_Client  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}