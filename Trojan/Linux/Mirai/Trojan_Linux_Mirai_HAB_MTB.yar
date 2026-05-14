
rule Trojan_Linux_Mirai_HAB_MTB{
	meta:
		description = "Trojan:Linux/Mirai.HAB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,1f 00 1f 00 02 00 00 "
		
	strings :
		$a_01_0 = {5b 75 64 70 62 79 70 61 73 73 5f 66 6c 6f 6f 64 5d 20 73 74 61 72 74 65 64 3a 20 28 27 25 64 27 29 } //30 [udpbypass_flood] started: ('%d')
		$a_01_1 = {5b 73 79 6e 5f 66 6c 6f 6f 64 5d 20 73 74 61 72 74 65 64 3a 20 28 27 25 64 27 29 } //1 [syn_flood] started: ('%d')
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*1) >=31
 
}