
rule Trojan_Win32_Ekstak_ASGO_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 ?? ?? 65 00 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 40 68 ?? ?? 65 00 ff 15 ?? ?? 65 00 a3 ?? ?? 65 00 c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}