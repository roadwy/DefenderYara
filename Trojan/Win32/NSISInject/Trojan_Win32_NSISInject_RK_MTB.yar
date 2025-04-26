
rule Trojan_Win32_NSISInject_RK_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 e4 03 55 f8 0f b6 02 33 c1 8b 4d e4 03 4d f8 88 01 8b 55 f8 83 c2 01 89 55 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RK_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c0 01 6b c0 14 01 c1 8b 45 10 2b 45 f4 83 e8 01 6b c0 14 89 14 24 } //1
		$a_01_1 = {c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_NSISInject_RK_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 70 67 72 61 76 65 64 65 73 2e 64 6c 6c } //1 opgravedes.dll
		$a_01_1 = {41 6e 6c 67 73 6f 70 67 61 76 65 72 2e 69 6e 69 } //1 Anlgsopgaver.ini
		$a_01_2 = {53 79 64 6c 69 67 2e 69 6e 69 } //1 Sydlig.ini
		$a_01_3 = {43 61 76 61 6c 69 65 72 65 64 5c 50 6f 72 74 75 6c 61 6b 6b 65 72 2e 69 6e 69 } //1 Cavaliered\Portulakker.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_NSISInject_RK_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 6e 69 6e 73 74 61 6c 6c 5c 52 68 6f 6d 62 6f 76 61 74 65 5c 43 61 63 68 75 63 68 61 73 } //1 Uninstall\Rhombovate\Cachuchas
		$a_01_1 = {52 61 66 66 69 61 73 5c 41 63 74 69 6f 6e 66 69 6c 6d 68 65 6c 74 65 5c 45 6c 69 6d 61 72 5c 54 75 72 6e 6b 6d 74 65 61 74 72 65 2e 69 6e 69 } //1 Raffias\Actionfilmhelte\Elimar\Turnkmteatre.ini
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 61 67 61 73 69 6e 5c 4f 73 74 69 6e 64 69 65 6e } //1 Software\Magasin\Ostindien
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}