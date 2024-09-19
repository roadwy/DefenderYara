
rule Trojan_Win32_Ekstak_ASGY_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 10 a1 ?? ?? 65 00 56 57 50 e8 ?? ?? ?? 00 8d 54 24 0c c7 44 24 0c 0c 00 00 00 8b 4c 24 1c c7 44 24 10 00 00 00 00 51 6a 00 6a 01 52 c7 44 24 24 00 00 00 00 ff 15 ?? ?? 65 00 8b f0 a1 ?? ?? 65 00 50 c7 44 24 0c 00 00 00 00 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}