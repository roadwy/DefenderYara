
rule Trojan_Win32_Tedy_PTC_MTB{
	meta:
		description = "Trojan:Win32/Tedy.PTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {ac 84 c0 74 ?? 30 07 47 39 cf 75 } //7
		$a_03_1 = {29 d2 50 57 52 52 68 ?? ?? ?? ?? 52 52 52 56 52 ff 15 } //2
	condition:
		((#a_03_0  & 1)*7+(#a_03_1  & 1)*2) >=9
 
}