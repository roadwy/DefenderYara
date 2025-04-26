
rule Worm_Win32_Autorun_NP{
	meta:
		description = "Worm:Win32/Autorun.NP,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 49 43 51 32 30 30 33 44 65 63 72 79 70 74 } //1 TICQ2003Decrypt
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 4e 65 74 77 6f 72 6b 5c 43 6f 6e 6e 65 63 74 69 6f 6e 73 5c 50 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //1 \Microsoft\Network\Connections\Pbk\rasphone.pbk
		$a_01_2 = {49 43 51 32 30 30 33 44 65 63 72 79 70 74 31 50 61 73 73 77 6f 72 64 46 6f 75 6e 64 } //1 ICQ2003Decrypt1PasswordFound
		$a_01_3 = {2e 63 6f 6d 2e 62 72 } //1 .com.br
		$a_01_4 = {54 43 61 6d 65 72 61 } //1 TCamera
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}