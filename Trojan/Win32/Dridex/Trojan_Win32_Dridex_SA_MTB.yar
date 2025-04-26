
rule Trojan_Win32_Dridex_SA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 03 31 [0-20] 8a 2c 3b [0-0a] 30 cd [0-10] 88 2c 07 83 c0 01 [0-06] 39 f8 [0-15] 0f [0-06] e9 } //1
		$a_01_1 = {73 6f 6d 65 77 68 61 74 74 79 70 65 64 72 4f 6d 6f 64 65 } //1 somewhattypedrOmode
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}