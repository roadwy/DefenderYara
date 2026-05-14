
rule Trojan_Win64_CookieStealer_AMTB{
	meta:
		description = "Trojan:Win64/CookieStealer!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {48 65 6c 6c 6f 20 66 72 6f 6d 20 63 6f 6f 6b 69 65 20 73 74 33 34 6c 33 72 21 } //Hello from cookie st34l3r!  1
		$a_80_1 = {5c 63 6f 6f 6b 69 65 2d 73 74 65 61 6c 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 63 6f 6f 6b 69 65 2d 73 74 65 61 6c 65 72 2e 70 64 62 } //\cookie-stealer\x64\Release\cookie-stealer.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}