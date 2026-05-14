
rule Trojan_Win32_Farfli_AFA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 50 6a 02 68 d0 c0 41 00 56 ff d7 56 ff 15 ?? ?? ?? ?? 6a 08 be ac c0 41 00 59 8d bd 5c ff ff ff f3 a5 66 a5 6a 40 33 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}