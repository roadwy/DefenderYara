
rule Trojan_Win32_Guloader_ASG_MTB{
	meta:
		description = "Trojan:Win32/Guloader.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {4f 75 74 73 70 61 6e 73 5c 48 65 72 62 5c 4d 6f 6c 69 6e 69 61 33 38 5c 44 75 6d 6d 79 73 70 69 6c 6c 65 72 65 2e 43 61 6d } //2 Outspans\Herb\Molinia38\Dummyspillere.Cam
		$a_01_1 = {53 6d 75 6b 6b 65 73 65 72 65 6e 64 65 25 5c 66 6e 75 67 67 65 6e 65 73 2e 4b 6f 6c } //1 Smukkeserende%\fnuggenes.Kol
		$a_01_2 = {57 68 61 74 73 6f 6d 65 76 65 72 5c 4a 79 6e 64 65 76 61 64 73 5c 49 6e 64 62 6f 66 6f 72 73 69 6b 72 69 6e 67 65 72 6e 65 32 32 38 5c 42 65 66 61 6c 65 74 2e 46 72 65 } //1 Whatsomever\Jyndevads\Indboforsikringerne228\Befalet.Fre
		$a_01_3 = {48 6f 65 6a 72 65 6c 69 6e 65 61 65 72 2e 53 76 69 } //1 Hoejrelineaer.Svi
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 53 75 6e 6b 65 74 31 39 31 5c 50 65 72 69 61 6f 72 74 69 74 69 73 } //1 Software\Sunket191\Periaortitis
		$a_01_5 = {54 65 6d 61 74 69 73 65 72 65 5c 48 6f 73 65 6b 72 61 65 6d 6d 65 72 65 6e 32 30 38 } //1 Tematisere\Hosekraemmeren208
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}