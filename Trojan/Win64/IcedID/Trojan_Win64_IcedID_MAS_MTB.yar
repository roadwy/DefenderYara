
rule Trojan_Win64_IcedID_MAS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6e 74 75 67 6a 68 73 68 61 67 73 64 6d 61 6a 68 } //01 00  ntugjhshagsdmajh
		$a_03_1 = {f0 00 22 20 0b 02 90 01 02 00 da 01 00 00 02 90 00 } //01 00 
		$a_01_2 = {54 62 61 6a 7a 75 72 71 45 68 } //01 00  TbajzurqEh
		$a_01_3 = {6e 47 78 63 70 50 31 41 32 58 } //01 00  nGxcpP1A2X
		$a_01_4 = {6f 4b 6c 69 52 55 4e 6f 32 39 } //01 00  oKliRUNo29
		$a_01_5 = {6f 5a 69 66 39 62 4b 6f 62 55 6c } //00 00  oZif9bKobUl
	condition:
		any of ($a_*)
 
}