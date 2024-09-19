
rule Trojan_Win32_Ekstak_ASGX_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 12 a3 7c bd 65 00 ff d7 66 85 c0 6a 10 0f 95 c3 ff d7 66 85 c0 7d 06 81 0e 00 00 00 02 6a 11 ff d7 66 85 c0 7d 06 81 0e 00 00 00 04 6a 00 ff 15 ?? ?? 65 00 84 db 74 06 81 0e ?? ?? ?? 00 8b c6 5f 5e 5b c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}