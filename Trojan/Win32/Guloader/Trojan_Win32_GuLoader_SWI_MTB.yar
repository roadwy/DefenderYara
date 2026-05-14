
rule Trojan_Win32_GuLoader_SWI_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SWI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {43 6f 73 6d 6f 67 6f 6e 69 73 74 32 35 35 2e 65 6c 65 } //1 Cosmogonist255.ele
		$a_81_1 = {50 65 72 73 6f 6e 61 6c 65 63 68 65 66 65 72 32 31 39 2e 67 61 6e } //1 Personalechefer219.gan
		$a_81_2 = {6c 75 78 65 6d 62 75 72 67 65 72 2e 73 6b 75 } //1 luxemburger.sku
		$a_81_3 = {70 72 6f 67 6e 6f 73 65 61 72 62 65 6a 64 65 72 6e 65 2e 64 61 74 } //1 prognosearbejderne.dat
		$a_81_4 = {5c 64 69 61 70 65 72 65 64 5c 75 64 61 72 62 65 6a 64 65 74 2e 68 74 6d } //1 \diapered\udarbejdet.htm
		$a_81_5 = {5c 75 6e 73 68 6f 75 74 65 64 5c 61 73 6b 65 74 72 65 74 73 2e 69 6e 69 } //1 \unshouted\asketrets.ini
		$a_81_6 = {5c 62 6c 6c 65 68 61 74 73 5c 43 65 72 61 6d 69 73 74 31 35 37 2e 69 6e 69 } //1 \bllehats\Ceramist157.ini
		$a_81_7 = {5c 61 6e 73 69 67 74 73 63 72 65 6d 65 6e 5c 53 70 69 72 69 74 69 73 74 2e 68 74 6d } //1 \ansigtscremen\Spiritist.htm
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}