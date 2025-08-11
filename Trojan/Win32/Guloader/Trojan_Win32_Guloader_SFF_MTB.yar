
rule Trojan_Win32_Guloader_SFF_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {55 6e 64 65 72 6c 69 76 65 6e 65 73 } //2 Underlivenes
		$a_81_1 = {53 74 6f 72 6b 65 6e 62 62 65 6e 65 2e 43 68 61 } //1 Storkenbbene.Cha
		$a_81_2 = {6b 76 61 6c 69 74 65 74 73 6d 73 73 69 67 74 } //1 kvalitetsmssigt
		$a_81_3 = {62 65 6e 65 66 69 63 65 6c 65 73 73 2e 69 6e 69 } //1 beneficeless.ini
		$a_81_4 = {62 65 73 6b 72 69 6e 67 65 72 6e 65 73 2e 6b 6c 6f } //1 beskringernes.klo
		$a_81_5 = {67 61 69 6e 66 75 6c 6c 79 2e 69 6e 69 } //1 gainfully.ini
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}