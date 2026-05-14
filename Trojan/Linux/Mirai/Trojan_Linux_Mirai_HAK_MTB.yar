
rule Trojan_Linux_Mirai_HAK_MTB{
	meta:
		description = "Trojan:Linux/Mirai.HAK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 63 20 2d 61 20 27 25 73 27 20 25 73 } //10 exec -a '%s' %s
		$a_01_1 = {5b 2b 5d 20 41 74 74 61 63 6b 20 73 74 61 72 74 65 64 } //20 [+] Attack started
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}