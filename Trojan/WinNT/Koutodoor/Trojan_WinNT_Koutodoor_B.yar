
rule Trojan_WinNT_Koutodoor_B{
	meta:
		description = "Trojan:WinNT/Koutodoor.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_08_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 72 00 6b 00 64 00 6f 00 6f 00 72 00 } //1 \Device\rkdoor
		$a_03_1 = {ff 75 fc 8d 85 fc fe ff ff 50 e8 90 16 55 8b ec 57 33 ff 39 7d 14 7e } //1
	condition:
		((#a_08_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}