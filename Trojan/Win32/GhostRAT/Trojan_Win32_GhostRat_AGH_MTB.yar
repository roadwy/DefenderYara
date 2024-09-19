
rule Trojan_Win32_GhostRat_AGH_MTB{
	meta:
		description = "Trojan:Win32/GhostRat.AGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 ff 54 24 4c 8b 84 24 8c 00 00 00 ff 70 20 83 c0 38 50 ff b4 24 9c 00 00 00 ff 54 24 54 8b 84 24 8c 00 00 00 6a 04 56 ff 70 2c 53 ff 54 24 38 8b 8c 24 8c 00 00 00 89 84 24 98 00 00 00 ff 71 2c 50 } //3
		$a_01_1 = {31 37 36 2e 32 32 31 2e 31 36 2e 31 36 37 } //2 176.221.16.167
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}