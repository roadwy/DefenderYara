
rule Trojan_Win32_Ekstak_ASFL_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 01 52 ff 15 90 01 03 00 8b c8 5e 41 f7 d9 1b c9 23 c8 33 c0 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}