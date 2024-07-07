
rule Trojan_Win32_Rozemyu_B{
	meta:
		description = "Trojan:Win32/Rozemyu.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 50 32 50 5c 43 6c 69 65 6e 74 5c 44 65 62 75 67 5c 43 6c 69 65 6e 74 2e 70 64 62 } //1 \P2P\Client\Debug\Client.pdb
		$a_01_1 = {5b 43 26 43 5d 20 28 25 73 29 20 2d 20 25 73 } //1 [C&C] (%s) - %s
		$a_01_2 = {5b 4e 61 6b 42 6f 74 5d 20 41 77 61 69 74 69 6e 67 20 55 44 50 20 44 61 74 61 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 6f 6e 20 25 64 } //1 [NakBot] Awaiting UDP Data Connection on %d
		$a_01_3 = {55 44 50 49 6e 69 74 } //1 UDPInit
		$a_01_4 = {58 45 4e 43 00 00 00 00 58 45 4e 52 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}