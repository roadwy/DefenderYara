
rule Trojan_Win32_Makoob_SERY_MTB{
	meta:
		description = "Trojan:Win32/Makoob.SERY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 00 6f 00 72 00 64 00 76 00 69 00 6e 00 65 00 6e 00 65 00 73 00 20 00 6c 00 6f 00 76 00 67 00 69 00 76 00 6e 00 69 00 6e 00 67 00 65 00 72 00 6e 00 65 00 73 00 } //1 bordvinenes lovgivningernes
		$a_01_1 = {76 00 6f 00 72 00 74 00 20 00 73 00 6b 00 6f 00 6c 00 64 00 65 00 6e 00 64 00 65 00 20 00 63 00 6f 00 6e 00 76 00 6f 00 6c 00 75 00 74 00 61 00 } //1 vort skoldende convoluta
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}