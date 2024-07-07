
rule Backdoor_Linux_Mirai_CE_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {77 67 65 74 25 32 30 68 74 74 70 3a 2f 2f 90 02 10 2f 90 02 08 2e 73 68 25 32 30 2d 4f 25 32 30 2d 25 33 45 25 32 30 2f 74 6d 70 2f 90 02 08 3b 73 68 25 32 30 2f 74 6d 70 2f 90 00 } //1
		$a_01_1 = {50 4f 53 54 20 2f 63 6f 6d 6d 61 6e 64 2e 70 68 70 20 48 54 54 50 2f 31 2e 31 } //1 POST /command.php HTTP/1.1
		$a_01_2 = {50 4f 53 54 20 2f 74 6d 42 6c 6f 63 6b 2e 63 67 69 20 48 54 54 50 2f 31 2e 31 } //1 POST /tmBlock.cgi HTTP/1.1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}