
rule Trojan_Win32_Amadey_TSA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.TSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 8b c3 c1 ea 04 8b ca c1 e1 04 03 ca 2b c1 03 c6 0f b6 44 04 ?? 32 85 04 10 40 00 83 c5 06 88 47 fd 8d 45 ff 3d 00 a2 06 00 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}