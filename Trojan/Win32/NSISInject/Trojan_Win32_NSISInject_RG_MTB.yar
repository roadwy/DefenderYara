
rule Trojan_Win32_NSISInject_RG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 53 57 ff 55 f8 90 02 20 8b c1 90 02 01 6a 0c 90 02 01 5e f7 fe 8a 82 90 01 04 30 04 39 41 3b cb 72 ea 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RG_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 56 6a 00 ff d7 53 6a 01 8b f8 56 57 e8 90 02 20 03 d2 03 d2 8b c1 2b c2 8a 90 01 05 30 14 39 41 3b ce 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RG_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 61 00 66 00 66 00 65 00 63 00 74 00 69 00 62 00 6c 00 65 00 } //1 CurrentVersion\Uninstall\affectible
		$a_01_1 = {76 00 61 00 75 00 63 00 68 00 65 00 72 00 69 00 61 00 63 00 65 00 61 00 65 00 2e 00 64 00 61 00 74 00 } //1 vaucheriaceae.dat
		$a_01_2 = {42 00 75 00 72 00 67 00 75 00 6e 00 64 00 65 00 72 00 65 00 37 00 } //1 Burgundere7
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_NSISInject_RG_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 00 6e 00 64 00 6f 00 76 00 65 00 72 00 66 00 6c 00 61 00 64 00 65 00 6e 00 2e 00 69 00 6e 00 69 00 } //1 andoverfladen.ini
		$a_01_1 = {53 00 65 00 6c 00 73 00 6b 00 61 00 62 00 73 00 6c 00 6f 00 6b 00 61 00 6c 00 65 00 72 00 73 00 2e 00 6c 00 6e 00 6b 00 } //1 Selskabslokalers.lnk
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 68 00 61 00 70 00 61 00 72 00 72 00 61 00 7a 00 } //1 Software\Chaparraz
		$a_01_3 = {53 00 63 00 61 00 70 00 68 00 6f 00 63 00 65 00 70 00 68 00 61 00 6c 00 69 00 63 00 2e 00 69 00 6e 00 69 00 } //1 Scaphocephalic.ini
		$a_01_4 = {52 00 65 00 70 00 72 00 6f 00 61 00 63 00 68 00 66 00 75 00 6c 00 2e 00 64 00 6c 00 6c 00 } //1 Reproachful.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}