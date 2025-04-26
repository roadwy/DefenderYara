
rule Trojan_Win32_Mokes_EW_MTB{
	meta:
		description = "Trojan:Win32/Mokes.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6b 75 6c 61 6a 6f 77 75 74 65 76 69 67 61 78 } //1 kulajowutevigax
		$a_01_1 = {70 6f 76 65 6e 69 73 6f 72 75 6a 75 64 75 63 6f 67 61 72 75 6c 6f 7a 75 79 65 } //1 povenisorujuducogarulozuye
		$a_01_2 = {76 65 6b 6f 77 69 74 61 6b 6f 72 75 6d 61 63 } //1 vekowitakorumac
		$a_01_3 = {6e 69 70 6f 73 75 62 75 6c 69 62 65 74 75 76 65 79 69 66 6f 7a 65 62 65 74 61 77 75 6a 65 6d } //1 niposubulibetuveyifozebetawujem
		$a_81_4 = {70 6f 66 61 76 75 77 75 70 6f 72 69 6b 65 74 61 6c 75 64 75 79 69 73 65 6b 65 6e 61 20 6b 6f 78 69 6b 65 72 65 77 61 63 75 7a 69 68 61 73 65 78 75 74 61 74 61 66 75 } //1 pofavuwuporiketaluduyisekena koxikerewacuzihasexutatafu
		$a_81_5 = {52 6f 7a 75 74 69 20 79 6f 67 75 6a 75 66 69 63 69 7a 61 72 6f 64 } //1 Rozuti yogujuficizarod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}