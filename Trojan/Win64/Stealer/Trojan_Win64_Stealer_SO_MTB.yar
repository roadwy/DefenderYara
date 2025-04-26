
rule Trojan_Win64_Stealer_SO_MTB{
	meta:
		description = "Trojan:Win64/Stealer.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {50 75 66 66 69 65 72 49 6e 64 75 73 } //2 PuffierIndus
		$a_81_1 = {47 75 6c 64 65 6e 52 75 63 68 65 20 66 6f 72 20 57 69 6e 64 6f 77 73 } //2 GuldenRuche for Windows
		$a_81_2 = {47 75 6c 64 65 6e 52 75 63 68 65 } //2 GuldenRuche
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}