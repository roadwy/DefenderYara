
rule Trojan_Win32_Guloader_CW_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 65 77 6f 6b 65 34 30 5c 65 6e 63 65 70 68 61 6c 6f 69 64 2e 6c 6e 6b } //1 Rewoke40\encephaloid.lnk
		$a_01_1 = {6b 65 76 6c 61 72 5c 74 65 6e 6f 72 73 61 78 65 73 2e 6c 69 76 } //1 kevlar\tenorsaxes.liv
		$a_01_2 = {6b 6e 61 63 6b 61 77 61 79 5c 6b 6c 61 74 67 6c 64 5c 52 67 64 79 6b 6b 65 72 32 32 37 } //1 knackaway\klatgld\Rgdykker227
		$a_01_3 = {4d 6f 72 62 72 64 72 65 73 5c 4c 65 6d 70 65 6c 73 65 72 6e 65 73 5c 79 6e 6b 73 6f 6d 73 74 65 } //1 Morbrdres\Lempelsernes\ynksomste
		$a_01_4 = {73 65 6b 73 61 67 65 73 69 6d 61 73 2e 66 72 75 } //1 seksagesimas.fru
		$a_01_5 = {73 6b 72 69 76 65 6c 69 6e 69 65 6e 5c 64 6f 65 67 6c 69 63 2e 70 72 6f } //1 skrivelinien\doeglic.pro
		$a_01_6 = {6f 76 65 72 73 61 6d 70 6c 65 64 5c 4f 70 69 75 6d 2e 47 72 69 } //1 oversampled\Opium.Gri
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}