
rule Trojan_Win32_Ekstak_CCJE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCJE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 ec 10 56 57 68 54 b0 65 00 6a 00 8d 44 24 14 6a 01 50 c7 44 24 1c 0c 00 00 00 c7 44 24 20 00 00 00 00 c7 44 24 24 00 00 00 00 ff 15 2c 82 65 00 8b 0d a0 bd 65 00 8b f0 51 c7 44 24 0c 00 00 00 00 ff 15 28 82 65 00 8d 54 24 08 52 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}