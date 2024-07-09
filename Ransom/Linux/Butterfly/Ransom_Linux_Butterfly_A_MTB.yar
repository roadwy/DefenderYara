
rule Ransom_Linux_Butterfly_A_MTB{
	meta:
		description = "Ransom:Linux/Butterfly.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 62 66 6c 79 } //1 .bfly
		$a_03_1 = {74 74 70 3a 2f 2f [0-56] 2e 6f 6e 69 6f 6e } //1
		$a_01_2 = {2d 2d 65 6e 63 72 79 70 74 20 2f 68 6f 6d 65 2f 62 75 74 74 65 72 66 6c 79 2f 64 61 74 61 2f } //1 --encrypt /home/butterfly/data/
		$a_01_3 = {2d 2d 64 65 63 72 79 70 74 20 2f 68 6f 6d 65 2f 62 75 74 74 65 72 66 6c 79 2f 64 61 74 61 2f 20 2d 2d 74 6f 72 } //1 --decrypt /home/butterfly/data/ --tor
		$a_01_4 = {2d 2d 64 65 63 72 79 70 74 20 2f 68 6f 6d 65 2f 62 75 74 74 65 72 66 6c 79 2f 64 61 74 61 2f 20 2d 2d 6b 65 79 20 2f 68 6f 6d 65 2f 62 75 74 74 65 72 66 6c 79 2f 62 75 74 74 65 72 66 6c 79 2f 6d 61 73 74 65 72 6b 65 79 73 2f 53 50 72 69 76 61 74 65 52 53 41 2e 70 65 6d } //1 --decrypt /home/butterfly/data/ --key /home/butterfly/butterfly/masterkeys/SPrivateRSA.pem
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}