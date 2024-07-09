
rule Trojan_BAT_Injector_SA_bit{
	meta:
		description = "Trojan:BAT/Injector.SA!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {6a 69 61 6f 77 75 70 61 69 6b 65 } //1 jiaowupaike
		$a_03_1 = {08 09 1e 58 91 08 09 91 1a 58 33 ?? 08 09 1c 58 91 08 09 91 19 58 33 ?? 08 09 18 58 91 08 09 91 17 58 33 ?? 08 09 1a 58 91 08 09 91 18 58 33 ?? 16 13 04 } //2
		$a_03_2 = {06 11 04 08 18 11 04 5a 09 58 1f 0a 58 91 08 09 1b 58 91 [0-05] 61 d2 9c } //2
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=5
 
}