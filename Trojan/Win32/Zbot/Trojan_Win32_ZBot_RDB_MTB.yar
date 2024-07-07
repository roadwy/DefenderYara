
rule Trojan_Win32_ZBot_RDB_MTB{
	meta:
		description = "Trojan:Win32/ZBot.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 89 45 84 8b 4d 84 03 4d 94 89 4d 84 8b 55 84 8a 02 2a 45 c4 8b 4d 84 88 01 83 7d 8c 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}