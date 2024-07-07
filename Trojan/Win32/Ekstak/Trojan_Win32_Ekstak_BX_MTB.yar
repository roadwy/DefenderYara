
rule Trojan_Win32_Ekstak_BX_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 ff 15 d0 46 65 00 56 ff 15 44 40 65 00 56 ff 15 3c 47 65 00 e9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}