
rule Ransom_MSIL_Ekati_A_MTB{
	meta:
		description = "Ransom:MSIL/Ekati.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 64 6f 77 6e 6c 6f 61 64 65 64 20 66 69 6c 65 20 66 72 6f 6d 20 54 6f 72 20 73 69 74 65 } //1 Successfully downloaded file from Tor site
		$a_81_1 = {61 64 76 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 6d 6f 64 65 20 64 69 73 61 62 6c 65 } //1 adv firewall set opmode mode disable
		$a_81_2 = {4d 6f 64 69 66 79 69 6e 67 20 66 69 72 65 77 61 6c 6c } //1 Modifying firewall
		$a_81_3 = {6f 6e 69 6f 6e 2e 6a 70 67 } //1 onion.jpg
		$a_81_4 = {6c 6f 63 6b 65 72 } //1 locker
		$a_81_5 = {6c 6f 67 67 65 72 } //1 logger
		$a_81_6 = {72 75 62 79 } //1 ruby
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}