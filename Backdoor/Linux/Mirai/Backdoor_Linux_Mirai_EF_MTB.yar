
rule Backdoor_Linux_Mirai_EF_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 61 6e 6b 6f 2d 61 70 70 2f } //1 /anko-app/
		$a_00_1 = {73 65 72 76 69 63 65 73 07 5f 64 6e 73 2d 73 64 04 5f 75 64 70 05 6c 6f 63 61 6c } //1
		$a_00_2 = {75 72 6e 3a 64 69 61 6c 2d 6d 75 6c 74 69 73 63 72 65 65 6e 2d 6f 72 67 3a 73 65 72 76 69 63 65 3a 64 69 61 6c 3a 31 } //1 urn:dial-multiscreen-org:service:dial:1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}