
rule Trojan_Win32_GuLoader_AYE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.AYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 00 6f 00 6e 00 6e 00 65 00 63 00 65 00 73 00 73 00 69 00 74 00 6f 00 75 00 73 00 6e 00 65 00 73 00 73 00 5c 00 43 00 6c 00 61 00 73 00 73 00 77 00 6f 00 72 00 6b 00 5c 00 53 00 74 00 61 00 6e 00 67 00 65 00 6e 00 5c 00 68 00 75 00 6d 00 6d 00 65 00 64 00 65 00 73 00 2e 00 64 00 6c 00 6c 00 } //1 Nonnecessitousness\Classwork\Stangen\hummedes.dll
		$a_01_1 = {53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 44 00 65 00 76 00 6f 00 69 00 63 00 65 00 73 00 } //1 Start Menu\Devoices
		$a_01_2 = {55 6e 69 6e 73 74 61 6c 6c 5c 43 65 72 76 69 63 69 70 6c 65 78 } //1 Uninstall\Cerviciplex
		$a_01_3 = {57 65 61 74 68 65 72 67 6c 65 61 6d 5c 54 69 64 73 73 6b 72 69 66 74 73 62 69 62 6c 69 6f 74 65 6b 65 74 2e 53 54 59 } //1 Weathergleam\Tidsskriftsbiblioteket.STY
		$a_01_4 = {41 67 65 64 6c 79 5c 42 41 4c 49 53 54 52 41 52 49 41 5c 4e 75 64 65 6c 73 75 70 70 65 2e 69 6e 69 } //1 Agedly\BALISTRARIA\Nudelsuppe.ini
		$a_01_5 = {44 65 74 65 6b 74 69 76 61 72 62 65 6a 64 65 72 73 5c 50 72 65 61 67 67 72 61 76 61 74 65 5c 46 65 6f 66 66 65 65 2e 75 6e 64 } //1 Detektivarbejders\Preaggravate\Feoffee.und
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}