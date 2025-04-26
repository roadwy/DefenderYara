
rule Trojan_Win32_Quasar_RT_MTB{
	meta:
		description = "Trojan:Win32/Quasar.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {6a 61 6e 74 6f 6b 65 6d 69 74 6b 6f 31 } //jantokemitko1  1
		$a_80_1 = {54 30 46 52 4e 48 4d 58 46 46 59 4b 4c 4c 4d 58 49 49 58 4b 58 49 } //T0FRNHMXFFYKLLMXIIXKXI  1
		$a_80_2 = {53 68 6f 70 61 72 61 47 72 69 7a 6c 69 30 31 } //ShoparaGrizli01  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}