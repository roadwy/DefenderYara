
rule Trojan_Win32_Ekstak_GAF_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 47 d5 69 00 ?? ?? ?? ?? 00 be 0a 00 d4 bd 14 99 ff f2 65 00 00 d4 00 00 ce 39 aa 43 00 00 01 00 04 00 } //10
		$a_03_1 = {2a 01 00 00 00 b7 ?? ?? ?? ?? 67 66 00 00 be 0a 00 d4 bd 14 99 92 21 66 00 00 d4 00 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}