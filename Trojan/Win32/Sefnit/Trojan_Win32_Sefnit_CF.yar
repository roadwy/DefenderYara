
rule Trojan_Win32_Sefnit_CF{
	meta:
		description = "Trojan:Win32/Sefnit.CF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff d6 b0 01 eb 3a 53 53 56 ff 15 } //1
		$a_01_1 = {2d 00 2d 00 69 00 64 00 6c 00 65 00 00 00 00 00 5c 00 72 00 75 00 6e 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1
		$a_01_2 = {5f 69 64 6c 65 5f 74 72 69 67 67 65 72 5f } //1 _idle_trigger_
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}