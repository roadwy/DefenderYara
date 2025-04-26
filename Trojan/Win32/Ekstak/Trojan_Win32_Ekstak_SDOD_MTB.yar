
rule Trojan_Win32_Ekstak_SDOD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.SDOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 d2 0a 00 54 dc 8d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}