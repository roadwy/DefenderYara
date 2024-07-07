
rule Trojan_BAT_DiscordRAT_RDB_MTB{
	meta:
		description = "Trojan:BAT/DiscordRAT.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 63 6f 72 64 20 72 61 74 } //1 Discord rat
		$a_01_1 = {44 69 73 61 62 6c 65 44 65 66 65 6e 64 65 72 } //1 DisableDefender
		$a_01_2 = {75 61 63 62 79 70 61 73 73 } //1 uacbypass
		$a_01_3 = {44 69 73 61 62 6c 65 46 69 72 65 77 61 6c 6c } //1 DisableFirewall
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}