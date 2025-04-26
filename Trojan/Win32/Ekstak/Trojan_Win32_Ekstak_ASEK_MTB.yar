
rule Trojan_Win32_Ekstak_ASEK_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_00_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 d2 73 67 00 44 d7 63 00 00 c0 0a 00 0d 15 b6 76 bd 90 63 00 00 68 06 } //5
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 69 36 70 00 db 99 [0-04] 0a 00 0d 15 b6 76 36 53 } //5
	condition:
		((#a_00_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}