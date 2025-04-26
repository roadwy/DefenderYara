
rule Spoofer_Win32_Arpspoof_A{
	meta:
		description = "Spoofer:Win32/Arpspoof.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 eb 14 ff d7 66 3d 50 00 } //1
		$a_01_1 = {8a 48 0e 8d 70 0e 83 e1 0f 33 d2 57 8a 54 8e 0c 8d 2c 8e 66 8b 4e 02 8b fa c1 ef 04 } //1
		$a_00_2 = {48 69 6a 61 63 6b 20 72 65 63 65 69 76 65 64 20 25 64 20 70 61 63 6b 65 74 73 } //1 Hijack received %d packets
		$a_00_3 = {54 61 74 6f 6c 20 25 64 20 68 6f 73 74 73 } //1 Tatol %d hosts
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}