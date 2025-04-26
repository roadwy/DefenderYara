
rule HackTool_Win64_JuicyPotato_LK_MTB{
	meta:
		description = "HackTool:Win64/JuicyPotato.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4a 75 69 63 79 50 6f 74 61 74 6f 4e 47 } //1 JuicyPotatoNG
		$a_01_1 = {62 79 20 64 65 63 6f 64 65 72 5f 69 74 20 26 20 73 70 6c 69 6e 74 65 72 5f 63 6f 64 65 } //1 by decoder_it & splinter_code
		$a_01_2 = {5b 2b 5d 20 45 78 70 6c 6f 69 74 20 73 75 63 63 65 73 73 66 75 6c 21 } //1 [+] Exploit successful!
		$a_01_3 = {5b 21 5d 20 43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 61 72 79 57 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 20 63 6f 64 65 20 25 64 } //1 [!] CryptStringToBinaryW failed with error code %d
		$a_01_4 = {6e 00 63 00 61 00 63 00 6e 00 5f 00 69 00 70 00 5f 00 74 00 63 00 70 00 } //1 ncacn_ip_tcp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}