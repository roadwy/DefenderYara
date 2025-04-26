
rule Trojan_Win32_Guloader_CA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 65 6c 74 70 6c 61 64 73 65 72 5c 4d 79 6c 69 6f 62 61 74 69 64 5c 42 65 77 65 61 72 69 65 64 5c 50 65 72 73 70 65 6b 74 69 76 72 69 67 2e 74 75 72 } //1 Teltpladser\Myliobatid\Bewearied\Perspektivrig.tur
		$a_01_1 = {73 75 70 70 6c 65 74 6f 72 79 25 5c 55 6e 64 65 72 74 6f 6e 65 72 6e 65 73 5c 70 6c 69 73 73 65 65 72 5c 53 76 69 6e 67 6c 65 6e 73 2e 52 65 67 32 } //1 suppletory%\Undertonernes\plisseer\Svinglens.Reg2
		$a_01_2 = {74 72 69 70 68 79 6c 69 6e 65 5c 42 6f 6c 69 67 74 69 6c 73 79 6e 65 6e 65 73 2e 69 6e 69 } //1 triphyline\Boligtilsynenes.ini
		$a_01_3 = {47 65 6e 6b 62 73 76 72 64 69 65 72 73 5c 6c 69 6e 64 62 65 72 67 5c 42 6c 69 6b 66 61 6e 67 65 74 5c 46 65 64 74 65 72 61 73 } //1 Genkbsvrdiers\lindberg\Blikfanget\Fedteras
		$a_01_4 = {53 65 63 75 6c 61 72 69 73 65 73 5c 43 79 74 6f 70 6c 61 73 6d 61 73 5c 52 61 73 70 6e 69 6e 67 65 72 73 5c 53 65 79 63 68 65 6c 6c 69 73 6b 65 73 2e 53 74 6f } //1 Secularises\Cytoplasmas\Raspningers\Seychelliskes.Sto
		$a_01_5 = {42 6f 72 74 67 61 61 72 5c 6d 6f 72 74 61 72 65 64 5c 49 72 69 64 65 73 63 65 5c 53 75 70 65 72 73 65 74 73 2e 55 6e 6c } //1 Bortgaar\mortared\Iridesce\Supersets.Unl
		$a_01_6 = {49 6e 67 72 61 69 6e 69 6e 67 5c 74 65 67 6e 65 62 67 65 72 6e 65 73 2e 69 6e 69 } //1 Ingraining\tegnebgernes.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}