
rule Trojan_Win32_InfoStealer_X_MTB{
	meta:
		description = "Trojan:Win32/InfoStealer.X!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 63 73 76 2e 70 6f 73 61 64 61 64 65 73 61 6e 74 69 61 67 6f 2e 63 6f 6d 2f } //01 00  http://csv.posadadesantiago.com/
		$a_01_1 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 7a 69 70 2d 63 6f 6d 70 72 65 73 73 65 64 } //01 00  Content-Type: application/x-zip-compressed
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 2f 68 6f 6d 65 2f 3f 69 64 3d 25 73 26 61 63 74 3d 77 62 69 26 76 65 72 3d 25 73 } //00 00  http://%s/home/?id=%s&act=wbi&ver=%s
	condition:
		any of ($a_*)
 
}