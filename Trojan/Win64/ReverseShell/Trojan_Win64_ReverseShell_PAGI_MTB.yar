
rule Trojan_Win64_ReverseShell_PAGI_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.PAGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 8b 45 fc 99 f7 7d 28 89 d0 48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 } //2
		$a_01_1 = {41 54 54 41 43 4b 45 52 5f 49 50 } //2 ATTACKER_IP
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}