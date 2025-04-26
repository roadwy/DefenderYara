
rule Trojan_Win32_Gamaredon_psyl_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyl!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 57 53 50 5b 8b d3 51 e8 e3 fc ff ff 59 e2 f7 5b 5f 5e 33 c0 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}