
rule Trojan_Win32_NSISInject_AG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 6f 6e 65 72 69 64 61 65 5c 53 75 62 65 72 69 6e 2e 69 6e 69 } //1 Poneridae\Suberin.ini
		$a_01_1 = {25 57 49 4e 44 49 52 25 5c 6b 6f 6d 6d 65 6e 74 61 72 66 61 63 69 6c 69 74 65 74 5c 52 65 6e 64 7a 69 6e 61 73 2e 53 75 70 } //1 %WINDIR%\kommentarfacilitet\Rendzinas.Sup
		$a_01_2 = {56 6f 6c 74 65 72 65 5c 47 65 6f 67 6f 6e 69 63 61 6c 2e 69 6e 69 } //1 Voltere\Geogonical.ini
		$a_01_3 = {69 6d 70 6c 69 63 61 74 69 76 65 6e 65 73 73 5c 50 69 63 6b 6c 6f 63 6b 5c 55 64 67 69 66 74 73 62 65 68 6f 76 65 74 73 5c 44 69 66 66 65 72 65 6e 74 69 61 6c 6c 69 67 6e 69 6e 67 73 73 79 73 74 65 6d 65 72 6e 65 73 2e 4b 75 6c } //1 implicativeness\Picklock\Udgiftsbehovets\Differentialligningssystemernes.Kul
		$a_01_4 = {63 61 69 6e 5c 44 75 63 74 69 6c 65 6e 65 73 73 2e 50 69 61 } //1 cain\Ductileness.Pia
		$a_01_5 = {47 75 69 6c 74 66 75 6c 5c 46 72 79 73 65 62 6f 6b 73 65 } //1 Guiltful\Frysebokse
		$a_01_6 = {53 6b 61 72 61 62 65 6e 73 5c 53 6b 69 62 73 64 72 65 6e 67 65 6e 65 39 32 5c 42 72 69 67 68 74 69 6e 67 5c 53 77 65 64 67 65 72 } //1 Skarabens\Skibsdrengene92\Brighting\Swedger
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}