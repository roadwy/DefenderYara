
rule Backdoor_Linux_Setag_gen_A{
	meta:
		description = "Backdoor:Linux/Setag.gen!A,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {31 32 43 55 70 64 61 74 65 47 61 74 65 73 00 } //1
		$a_00_1 = {31 31 43 55 70 64 61 74 65 42 69 6c 6c 00 } //1 ㄱ啃摰瑡䉥汩l
		$a_00_2 = {2f 74 6d 70 2f 67 61 74 65 73 2e 6c 6f 63 6b 00 } //1 琯灭术瑡獥氮捯k
		$a_00_3 = {2f 74 6d 70 2f 62 69 6c 6c 2e 6c 6f 63 6b 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}