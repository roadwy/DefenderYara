
rule Trojan_Win32_DarkKomet_RT_MTB{
	meta:
		description = "Trojan:Win32/DarkKomet.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {6e 39 50 77 6f 61 45 6c } //1 n9PwoaEl
		$a_81_1 = {5d 45 5f 4c 61 7b 63 51 65 3b 67 70 69 76 6b 58 6d 50 6f } //1 ]E_La{cQe;gpivkXmPo
		$a_81_2 = {58 7a 62 55 44 68 43 6d 78 75 53 6c } //1 XzbUDhCmxuSl
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}