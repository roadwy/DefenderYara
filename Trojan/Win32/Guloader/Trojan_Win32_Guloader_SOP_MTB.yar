
rule Trojan_Win32_Guloader_SOP_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {61 64 66 72 64 20 74 76 65 62 6f 70 6c 61 6e 74 65 2e 65 78 65 } //1 adfrd tveboplante.exe
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 53 74 72 69 6b 6b 65 6d 61 73 6b 69 6e 65 73 39 30 5c 72 75 73 6b 75 72 73 65 74 } //1 Software\Strikkemaskines90\ruskurset
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 6d 61 74 65 72 69 61 6c 65 5c 6e 6f 6e 64 65 6d 6f 6e 73 74 72 61 74 69 76 65 6e 65 73 73 } //1 Software\materiale\nondemonstrativeness
		$a_81_3 = {2e 5c 73 61 6d 6d 65 6e 73 74 79 6b 6e 69 6e 67 73 2e 63 65 6e } //1 .\sammenstyknings.cen
		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 4d 61 72 63 68 65 72 65 6e 64 65 73 5c } //1 Software\Marcherendes\
		$a_81_5 = {25 42 69 6e 64 69 6e 67 6c 79 32 35 25 5c 73 65 72 76 69 63 65 74 65 6b 6e 69 6b 65 72 65 73 } //1 %Bindingly25%\serviceteknikeres
		$a_81_6 = {53 6f 66 74 77 61 72 65 5c 53 6b 75 6c 64 72 65 6e 64 65 73 5c 50 65 73 73 61 72 65 74 73 } //1 Software\Skuldrendes\Pessarets
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}