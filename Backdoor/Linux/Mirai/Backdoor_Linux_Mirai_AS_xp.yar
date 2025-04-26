
rule Backdoor_Linux_Mirai_AS_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AS!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 46 4f 4b 4c 4b 51 56 50 43 56 4d 50 } //1 cFOKLKQVPCVMP
		$a_01_1 = {51 57 52 47 50 54 4b 51 4d 50 } //1 QWRGPTKQMP
		$a_01_2 = {4c 43 4f 47 51 47 50 54 47 50 } //1 LCOGQGPTGP
		$a_01_3 = {50 4f 53 54 20 2f 63 64 6e 2d 63 67 69 2f } //1 POST /cdn-cgi/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}