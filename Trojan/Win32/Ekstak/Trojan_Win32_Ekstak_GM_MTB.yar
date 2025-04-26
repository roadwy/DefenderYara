
rule Trojan_Win32_Ekstak_GM_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {84 81 c2 5c b9 85 30 81 c2 69 9a 5b 8b 29 d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}