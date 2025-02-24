
rule Trojan_Win32_GuLoader_RSJ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 72 65 70 6c 61 73 74 65 72 5c 75 6e 69 6e 74 65 72 70 6c 65 61 64 65 64 } //1 Software\replaster\uninterpleaded
		$a_81_1 = {52 65 63 61 6e 74 73 5c 6b 69 72 73 65 62 72 73 74 65 6e 5c 72 68 65 73 75 73 70 6f 73 69 74 69 76 } //1 Recants\kirsebrsten\rhesuspositiv
		$a_81_2 = {39 39 5c 6d 75 6c 74 69 70 6c 69 63 65 72 65 5c 6d 6f 72 74 69 66 79 2e 50 75 6e } //1 99\multiplicere\mortify.Pun
		$a_81_3 = {24 24 5c 47 72 65 63 69 61 6e 69 7a 65 5c 74 75 72 72 69 74 65 6c 6c 69 64 61 65 2e 69 6e 69 } //1 $$\Grecianize\turritellidae.ini
		$a_81_4 = {25 55 6e 64 65 72 67 72 75 6e 64 73 62 61 6e 65 25 5c 41 6b 6b 75 73 61 74 69 76 6f 62 6a 65 6b 74 65 72 6e 65 2e 54 61 6e } //1 %Undergrundsbane%\Akkusativobjekterne.Tan
		$a_81_5 = {6d 65 63 68 61 6e 69 63 61 6c 69 7a 61 74 69 6f 6e 73 2e 62 6c 61 } //1 mechanicalizations.bla
		$a_81_6 = {72 65 67 61 6c 65 72 73 2e 6a 70 67 } //1 regalers.jpg
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}