
rule PWS_BAT_Lordix_A_MTB{
	meta:
		description = "PWS:BAT/Lordix.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {52 00 69 00 70 00 70 00 6c 00 65 00 } //1 Ripple
		$a_01_1 = {4c 00 69 00 74 00 65 00 63 00 6f 00 69 00 6e 00 } //1 Litecoin
		$a_01_2 = {4d 00 6f 00 6e 00 65 00 72 00 6f 00 } //1 Monero
		$a_01_3 = {45 00 74 00 68 00 65 00 72 00 65 00 75 00 6d 00 } //1 Ethereum
		$a_01_4 = {42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 } //1 Bitcoin
		$a_01_5 = {50 00 52 00 4f 00 43 00 4d 00 4f 00 4e 00 } //1 PROCMON
		$a_01_6 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 20 00 47 00 72 00 61 00 70 00 68 00 69 00 63 00 73 00 20 00 41 00 64 00 61 00 70 00 74 00 65 00 72 00 } //1 VirtualBox Graphics Adapter
		$a_01_7 = {5c 00 4f 00 70 00 65 00 72 00 61 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 70 00 65 00 72 00 61 00 20 00 53 00 74 00 61 00 62 00 6c 00 65 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //1 \Opera Software\Opera Stable\Login Data
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}