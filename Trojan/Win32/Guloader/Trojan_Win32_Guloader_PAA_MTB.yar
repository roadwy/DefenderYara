
rule Trojan_Win32_Guloader_PAA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {61 61 72 68 75 73 68 6f 74 65 6c 6c 65 72 6e 65 2e 6b 61 62 } //1 aarhushotellerne.kab
		$a_81_1 = {62 6f 6d 6d 65 64 65 73 2e 70 65 64 } //1 bommedes.ped
		$a_81_2 = {69 6e 64 68 65 6e 74 65 64 65 73 2e 6c 73 6c } //1 indhentedes.lsl
		$a_81_3 = {73 61 65 6c 67 65 72 6e 65 2e 66 6f 72 } //1 saelgerne.for
		$a_81_4 = {76 69 6c 6a 65 73 74 72 6b 74 2e 62 65 73 } //1 viljestrkt.bes
		$a_81_5 = {68 61 6e 64 6c 69 6e 67 73 70 6c 61 6e 65 72 5c 70 72 6f 67 72 61 6d 73 6b 72 69 76 6e 69 6e 67 65 72 73 2e 6c 6e 6b } //1 handlingsplaner\programskrivningers.lnk
		$a_81_6 = {54 75 72 69 73 74 70 72 6f 70 61 67 61 6e 64 61 65 72 6e 65 5c 62 65 74 61 6c 69 6e 67 73 72 65 67 6c 65 72 6e 65 2e 6a 70 67 } //1 Turistpropagandaerne\betalingsreglerne.jpg
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}