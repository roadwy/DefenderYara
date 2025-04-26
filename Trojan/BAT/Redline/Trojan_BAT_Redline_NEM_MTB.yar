
rule Trojan_BAT_Redline_NEM_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 2d 02 07 6f ?? 00 00 0a 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 0c 06 72 ?? 0e 00 70 08 28 ?? 01 00 0a 6f ?? 01 00 0a 26 07 17 58 0b 07 02 6f ?? 00 00 0a 32 ca } //10
		$a_01_1 = {4e 00 6f 00 72 00 64 00 56 00 70 00 6e 00 2e 00 65 00 78 00 65 00 2a 00 4d 00 79 00 47 00 54 00 6f 00 4d 00 79 00 47 00 6b 00 65 00 6e 00 73 00 2e 00 74 00 4d 00 79 00 47 00 78 00 74 00 } //5 NordVpn.exe*MyGToMyGkens.tMyGxt
		$a_01_2 = {63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 2e 00 73 00 71 00 6c 00 69 00 74 00 65 00 } //5 cookies.sqlite
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=20
 
}