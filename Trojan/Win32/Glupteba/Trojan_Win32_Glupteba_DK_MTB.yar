
rule Trojan_Win32_Glupteba_DK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 db 74 01 ea 31 1f 21 d1 81 c2 30 90 71 65 81 c7 04 00 00 00 81 ee 37 11 bd 92 39 c7 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}