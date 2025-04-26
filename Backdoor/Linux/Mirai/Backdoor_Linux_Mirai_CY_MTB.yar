
rule Backdoor_Linux_Mirai_CY_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {77 67 65 74 2b 68 74 74 70 3a 2f 2f [0-20] 2b 2d 4f 2b 2d 3e [0-02] 2f 74 6d 70 2f [0-08] 3b 73 68 2b 2f 74 6d 70 2f [0-08] 26 69 70 76 3d 30 } //1
		$a_01_1 = {50 4f 53 54 20 2f 47 70 6f 6e 46 6f 72 6d 2f 64 69 61 67 5f 46 6f 72 6d 3f } //1 POST /GponForm/diag_Form?
		$a_01_2 = {58 57 65 62 50 61 67 65 4e 61 6d 65 3d 64 69 61 67 26 64 69 61 67 5f 61 63 74 69 6f 6e 3d 70 69 6e 67 26 77 61 6e 5f 63 6f 6e 6c 69 73 74 3d 30 26 64 65 73 74 5f 68 6f 73 74 3d } //1 XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}