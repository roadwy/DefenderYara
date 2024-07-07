
rule Backdoor_Linux_Mirai_BI_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BI!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {77 35 71 36 68 65 33 64 62 72 73 67 6d 63 6c 6b 69 75 34 74 6f 31 38 6e 70 61 76 6a 37 30 32 66 } //1 w5q6he3dbrsgmclkiu4to18npavj702f
		$a_00_1 = {6b 69 6c 6c 61 6c 6c 62 6f 74 73 } //1 killallbots
		$a_00_2 = {6e 70 78 78 6f 75 64 69 66 66 65 65 67 67 61 61 63 73 63 73 } //1 npxxoudiffeeggaacscs
		$a_00_3 = {2f 64 65 76 2f 46 54 57 44 54 31 30 31 5f 77 61 74 63 68 64 6f 67 } //1 /dev/FTWDT101_watchdog
		$a_00_4 = {61 6a 77 6c 69 67 66 } //1 ajwligf
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}