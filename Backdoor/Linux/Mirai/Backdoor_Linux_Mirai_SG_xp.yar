
rule Backdoor_Linux_Mirai_SG_xp{
	meta:
		description = "Backdoor:Linux/Mirai.SG!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 6f 68 6f 20 62 6f 74 6e 65 74 } //1 hoho botnet
		$a_00_1 = {64 76 72 2e 6c 73 74 } //1 dvr.lst
		$a_00_2 = {73 70 6f 6f 66 65 64 } //1 spoofed
		$a_00_3 = {2e 2f 2e 61 6b 61 6d 65 } //1 ./.akame
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}